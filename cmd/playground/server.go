// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Kinds of text the playground scans.
const (
	kindPrompt   = "prompt"   // a user prompt: /guardrail/scan text
	kindDocument = "document" // third-party content (RAG): /guardrail/scan documents
	kindTool     = "tool"     // an MCP tool description: /guardrail/scan/tools
)

// server is the playground proxy.
type server struct {
	cfg      config
	limits   *limiter
	inFlight chan struct{}
	client   *http.Client
	stats    stats
}

// stats are the only thing the proxy records: counters, logged every
// STATS_INTERVAL and reset. No content, no addresses.
type stats struct {
	allowed, blocked, rateLimited, busy, rejected, failed atomic.Int64
}

func newServer(cfg config) *server {
	return &server{
		cfg:      cfg,
		limits:   newLimiter(cfg.PerMinute, cfg.PerDay, cfg.GlobalPerMin, cfg.MaxTracked),
		inFlight: make(chan struct{}, cfg.MaxInFlight),
		// No redirects: the gateway never sends one, and following one could
		// carry the key elsewhere.
		client: &http.Client{
			Timeout:       cfg.GatewayTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// run sweeps idle clients from the limiter and logs the counters.
func (s *server) run(ctx context.Context) {
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	report := time.NewTicker(s.cfg.StatsInterval)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			s.limits.sweep()
		case <-report.C:
			s.logStats()
		}
	}
}

func (s *server) logStats() {
	slog.Info("playground stats",
		"allowed", s.stats.allowed.Swap(0), "blocked", s.stats.blocked.Swap(0),
		"rate_limited", s.stats.rateLimited.Swap(0), "busy", s.stats.busy.Swap(0),
		"rejected", s.stats.rejected.Swap(0), "failed", s.stats.failed.Swap(0),
		"tracked_clients", s.limits.tracked())
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("OPTIONS /v1/scan", s.preflight)
	mux.HandleFunc("POST /v1/scan", s.scan)
	return headers(mux)
}

// headers sets what every response carries: no caching, no sniffing, and
// nothing to embed or frame.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// cors checks the Origin header and sets the CORS headers for an allowed
// origin. It answers 403 and returns false for any other origin, and for
// requests without one unless ALLOW_NO_ORIGIN is set.
func (s *server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if s.cfg.AllowNoOrigin {
			return true
		}
		writeError(w, http.StatusForbidden, "origin_not_allowed", "requests must come from the playground page")
		return false
	}
	if !s.cfg.AllowedOrigins[origin] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "origin not allowed")
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", "Retry-After")
	return true
}

func (s *server) preflight(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		s.stats.rejected.Add(1)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

// scanRequest is the body of POST /v1/scan.
type scanRequest struct {
	Text           string `json:"text"`
	Kind           string `json:"kind"`            // prompt (default), document or tool
	TurnstileToken string `json:"turnstile_token"` // only when TURNSTILE_SECRET is set
}

// scanResult is the answer of POST /v1/scan.
type scanResult struct {
	Decision  string     `json:"decision"` // allowed or blocked
	Kind      string     `json:"kind"`
	Score     float64    `json:"score"` // the fused injection score the decision used
	Label     string     `json:"label"` // BENIGN or the detected category
	DecidedBy string     `json:"decided_by,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Layers    *layers    `json:"layers"` // null when the gateway does not explain (before v0.2.2)
	Rules     []string   `json:"rules,omitempty"`
	Signals   []string   `json:"signals,omitempty"`   // MCP poisoning signals (tool)
	Sanitizer *sanitizer `json:"sanitizer,omitempty"` // prompt and document
	LatencyMs int64      `json:"latency_ms"`
}

type layers struct {
	L1 *float64 `json:"l1"`
	L2 *float64 `json:"l2"`
	L3 *float64 `json:"l3"`
}

type sanitizer struct {
	AnomalyScore float64  `json:"anomaly_score"`
	BytesRemoved int      `json:"bytes_removed"`
	Findings     []string `json:"findings"` // tag_chars, bidi, removed_chars
}

func (s *server) scan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !s.cors(w, r) {
		s.stats.rejected.Add(1)
		return
	}
	switch v, wait := s.limits.allow(s.clientIP(r)); v {
	case limited:
		s.stats.rateLimited.Add(1)
		retryAfter(w, wait)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many scans from your address; try again later")
		return
	case busy:
		s.stats.busy.Add(1)
		retryAfter(w, wait)
		writeError(w, http.StatusServiceUnavailable, "busy", "the playground is busy; try again shortly")
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		s.stats.rejected.Add(1)
		writeError(w, http.StatusUnsupportedMediaType, "bad_content_type", "send application/json")
		return
	}
	req, status, msg := s.readRequest(w, r)
	if status != 0 {
		s.stats.rejected.Add(1)
		writeError(w, status, "invalid_request", msg)
		return
	}
	if s.cfg.TurnstileSecret != "" && !s.verifyTurnstile(r.Context(), req.TurnstileToken, r) {
		s.stats.rejected.Add(1)
		writeError(w, http.StatusForbidden, "challenge_failed", "the anti-abuse check failed; reload the page")
		return
	}
	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		s.stats.busy.Add(1)
		retryAfter(w, 2*time.Second)
		writeError(w, http.StatusServiceUnavailable, "busy", "the playground is busy; try again shortly")
		return
	}

	res, err := s.callGateway(r.Context(), req)
	if err != nil {
		s.stats.failed.Add(1)
		var ge gatewayError
		if errors.As(err, &ge) && ge.status == http.StatusRequestEntityTooLarge {
			writeError(w, http.StatusRequestEntityTooLarge, "too_long", "the text is too long to scan")
			return
		}
		// The cause is logged without the text or the client.
		slog.Warn("gateway call failed", "kind", req.Kind, "err", err)
		writeError(w, http.StatusBadGateway, "scanner_unavailable", "the scanner is unavailable; try again later")
		return
	}
	if res.Decision == "blocked" {
		s.stats.blocked.Add(1)
	} else {
		s.stats.allowed.Add(1)
	}
	res.LatencyMs = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, res)
}

// readRequest reads and checks the body. A non-zero status is the error to
// answer with.
func (s *server) readRequest(w http.ResponseWriter, r *http.Request) (scanRequest, int, string) {
	var req scanRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return req, http.StatusRequestEntityTooLarge, "request body too large"
		}
		return req, http.StatusBadRequest, "could not read the body"
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		return req, http.StatusBadRequest, "body must be {\"text\": ..., \"kind\": ...}"
	}
	if req.Kind == "" {
		req.Kind = kindPrompt
	}
	switch {
	case req.Kind != kindPrompt && req.Kind != kindDocument && req.Kind != kindTool:
		return req, http.StatusBadRequest, "kind must be prompt, document or tool"
	case strings.TrimSpace(req.Text) == "":
		return req, http.StatusBadRequest, "text is required"
	case len(req.Text) > s.cfg.MaxInput:
		return req, http.StatusRequestEntityTooLarge, "text is longer than " + strconv.Itoa(s.cfg.MaxInput) + " bytes"
	case !utf8.ValidString(req.Text):
		return req, http.StatusBadRequest, "text must be UTF-8"
	}
	return req, 0, ""
}

// clientIP is the address the limiter counts: the TCP peer, or the address
// a trusted reverse proxy put in CLIENT_IP_HEADER.
func (s *server) clientIP(r *http.Request) netip.Addr {
	if h := s.cfg.ClientIPHeader; h != "" {
		v := r.Header.Get(h)
		if strings.EqualFold(h, "X-Forwarded-For") {
			// The last entry is the one the proxy in front appended; earlier
			// ones are whatever the client sent.
			if i := strings.LastIndexByte(v, ','); i >= 0 {
				v = v[i+1:]
			}
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return a
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr()
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a, _ := netip.ParseAddr(host)
	return a // the zero Addr: all unparseable peers share one bucket
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(max(d, time.Second).Seconds()))))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// verifyTurnstile checks a Cloudflare Turnstile token (TURNSTILE_SECRET).
func (s *server) verifyTurnstile(ctx context.Context, token string, r *http.Request) bool {
	if token == "" || len(token) > 2048 {
		return false
	}
	form := url.Values{"secret": {s.cfg.TurnstileSecret}, "response": {token}}
	if ip := s.clientIP(r); ip.IsValid() {
		form.Set("remoteip", ip.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TurnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("turnstile verify failed", "err", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return false
	}
	return out.Success
}
