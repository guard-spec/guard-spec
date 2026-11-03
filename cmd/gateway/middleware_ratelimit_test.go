package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/promptshield/promptshield/internal/ratelimit"
)

func TestRateLimitDefault(t *testing.T) {
	h := startGateway(t, "", func(gw *gateway) {
		gw.limits = newRateLimiter(ratelimit.Limits{RPM: 2}, nil)
	})
	for i := range 2 {
		if resp, body := h.post(t, "/v1/chat/completions", clean, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
		}
	}
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429: %s", resp.StatusCode, body)
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || s < 1 || s > 30 {
		t.Errorf("Retry-After = %q, want 1..30 seconds", resp.Header.Get("Retry-After"))
	}
	var e struct {
		Error struct{ Message, Type, Code string }
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatal(err)
	}
	if e.Error.Code != "rate_limit_exceeded" || e.Error.Type != "requests" || e.Error.Message == "" {
		t.Errorf("error body = %s", body)
	}
	// A refused request writes no audit row and never reaches the guard.
	h.gw.audit.wait()
	h.rec.mu.Lock()
	rows := len(h.rec.rows)
	h.rec.mu.Unlock()
	if rows != 2 {
		t.Errorf("audit rows = %d, want 2", rows)
	}
}

func TestRateLimitPerKeyOverride(t *testing.T) {
	var rpm, tpm *int64
	var lookups atomic.Int32
	lookup := func(_ context.Context, org uuid.UUID, hash string) (*int64, *int64, error) {
		lookups.Add(1)
		if org != devOrg || hash == "" {
			return nil, nil, errors.New("unexpected key")
		}
		return rpm, tpm, nil
	}
	zero := int64(0)
	rpm = &zero // 0: unlimited, despite the default of 1
	h := startGateway(t, "", func(gw *gateway) {
		gw.limits = newRateLimiter(ratelimit.Limits{RPM: 1}, lookup)
	})
	for i := range 5 {
		if resp, body := h.post(t, "/v1/chat/completions", clean, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
		}
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("lookups = %d, want 1 (cached)", n)
	}
}

func TestRateLimitTokens(t *testing.T) {
	h := startGateway(t, "", func(gw *gateway) {
		gw.limits = newRateLimiter(ratelimit.Limits{TPM: 20}, nil)
	})
	// clean is about 60 bytes, so 15 estimated tokens.
	if resp, body := h.post(t, "/v1/chat/completions", clean, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != http.StatusTooManyRequests || !json.Valid([]byte(body)) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var e struct{ Error struct{ Type string } }
	_ = json.Unmarshal([]byte(body), &e)
	if e.Error.Type != "tokens" {
		t.Errorf("type = %q, want tokens", e.Error.Type)
	}
}

func TestLookupFailureUsesDefaults(t *testing.T) {
	r := newRateLimiter(ratelimit.Limits{RPM: 7}, func(context.Context, uuid.UUID, string) (*int64, *int64, error) {
		return nil, nil, errors.New("db down")
	})
	if got := r.limits(context.Background(), devOrg, "h"); got.RPM != 7 {
		t.Errorf("limits = %+v, want the default", got)
	}
}

func TestLoadOpsConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg, err := loadOpsConfig(env(nil))
	if err != nil || cfg.MetricsAddr != ":9090" || cfg.Propagate || cfg.TenantLabels || !cfg.RateLimit.Unlimited() {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = loadOpsConfig(env(map[string]string{"RATE_LIMIT_RPM": "60", "RATE_LIMIT_TPM": "1000",
		"OTEL_PROPAGATE_UPSTREAM": "true", "METRICS_ADDR": "off"}))
	if err != nil || cfg.RateLimit.RPM != 60 || cfg.RateLimit.TPM != 1000 || !cfg.Propagate || cfg.MetricsAddr != "off" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, bad := range []map[string]string{{"RATE_LIMIT_RPM": "-1"}, {"RATE_LIMIT_TPM": "x"},
		{"OTEL_PROPAGATE_UPSTREAM": "maybe"}, {"METRICS_TENANT_LABELS": "2"}} {
		if _, err := loadOpsConfig(env(bad)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
