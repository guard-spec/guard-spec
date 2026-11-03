// Package proxy forwards sanitized requests to an OpenAI-compatible upstream.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// DefaultTimeout is generous because a local model can spend tens of seconds
	// loading, and a non-streaming upstream sends no headers until it has finished.
	DefaultTimeout = 5 * time.Minute

	connectTimeout   = 10 * time.Second
	maxResponseBytes = 64 << 20
	maxErrorBytes    = 64 << 10
	maxMessageLen    = 512
)

// Config describes the upstream. Key is optional.
type Config struct {
	BaseURL string        // for example http://host:11434/v1
	Key     string        // sent as a bearer token when set
	Timeout time.Duration // time to first byte, and longest silence after it
}

// Proxy sends requests to one upstream.
type Proxy struct {
	base    string
	key     string
	timeout time.Duration
	client  *http.Client
}

// Error is an upstream failure in a form that is safe to show the client.
type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter string
	cause      error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.cause)
	}
	return fmt.Sprintf("%s: upstream status %d", e.Code, e.Status)
}

func (e *Error) Unwrap() error { return e.cause }

// New validates cfg and builds a Proxy.
func New(cfg Config) (*Proxy, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("upstream url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("upstream url must be an absolute http or https url")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Proxy{
		base:    strings.TrimRight(cfg.BaseURL, "/"),
		key:     cfg.Key,
		timeout: cfg.Timeout,
		client: &http.Client{
			// No client-wide Timeout: it would also cut off a long stream.
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
				TLSHandshakeTimeout:   connectTimeout,
				ResponseHeaderTimeout: cfg.Timeout,
				DisableCompression:    true, // gzip would buffer an event stream
				MaxIdleConnsPerHost:   32,
				IdleConnTimeout:       90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Forward posts body to base+path. The request is built from scratch, so no
// client header can reach the upstream. A non-2xx status comes back as *Error.
// The caller must Close the Response.
func (p *Proxy) Forward(ctx context.Context, path string, body []byte) (*Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, classify(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "") // keep Go's default out
	if p.key != "" {
		req.Header.Set("Authorization", "Bearer "+p.key)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		cancel()
		return nil, classify(err)
	}

	r := &Response{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		body:        resp.Body,
		cancel:      cancel,
		idle:        p.timeout,
	}
	r.timer = time.AfterFunc(p.timeout, func() {
		r.timedOut.Store(true)
		cancel()
	})
	r.timer.Stop()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer r.Close()
		return nil, statusError(resp, r)
	}
	return r, nil
}

// Response is a successful upstream response, read incrementally.
type Response struct {
	Status      int
	ContentType string

	body     io.ReadCloser
	cancel   context.CancelFunc
	idle     time.Duration
	timer    *time.Timer
	timedOut atomic.Bool
}

// Stream reports whether the body is an event stream.
func (r *Response) Stream() bool {
	return strings.HasPrefix(strings.ToLower(r.ContentType), "text/event-stream")
}

// Read cancels the upstream if no data arrives for the configured timeout.
// The clock runs only during the read, so a slow client is not blamed on it.
func (r *Response) Read(p []byte) (int, error) {
	r.timer.Reset(r.idle)
	n, err := r.body.Read(p)
	r.timer.Stop()
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}
	if r.timedOut.Load() {
		return n, timeoutError(err)
	}
	return n, classify(err)
}

// ReadAll returns the whole body of a non-streaming response.
func (r *Response) ReadAll() ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, &Error{Status: http.StatusBadGateway, Code: "upstream_error",
			Message: "upstream response too large"}
	}
	return data, nil
}

// Close stops the upstream request.
func (r *Response) Close() {
	r.timer.Stop()
	r.cancel()
	_ = r.body.Close()
}

func timeoutError(cause error) *Error {
	return &Error{Status: http.StatusGatewayTimeout, Code: "upstream_timeout",
		Message: "upstream timed out", cause: cause}
}

// classify hides transport details: they name internal hosts and ports.
func classify(err error) *Error {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return timeoutError(err)
	}
	return &Error{Status: http.StatusBadGateway, Code: "upstream_unavailable",
		Message: "upstream unavailable", cause: err}
}

// statusError maps an upstream failure. A 4xx is about the request, so its
// status and message are useful to the client. A 5xx is about the upstream, and
// an auth failure is about the gateway's own credentials: both become a 502, so a
// client never sees an upstream 500 or 503 as if the gateway itself had failed.
func statusError(resp *http.Response, body io.Reader) *Error {
	status := resp.StatusCode
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden ||
		status == http.StatusProxyAuthRequired:
		slog.Error("upstream rejected gateway credentials", "status", status)
		return &Error{Status: http.StatusBadGateway, Code: "upstream_auth_failed",
			Message: "upstream rejected the gateway's credentials"}
	case status >= 400 && status <= 499:
		return &Error{Status: status, Code: "upstream_error",
			Message:    upstreamMessage(body, status),
			RetryAfter: resp.Header.Get("Retry-After")}
	case status >= 500 && status <= 599:
		slog.Warn("upstream error", "status", status)
		return &Error{Status: http.StatusBadGateway, Code: "upstream_error", Message: "upstream error",
			RetryAfter: resp.Header.Get("Retry-After")}
	default:
		return &Error{Status: http.StatusBadGateway, Code: "upstream_error",
			Message: "unexpected upstream response"}
	}
}

// upstreamMessage reads the OpenAI error shape, or the flat one some servers use.
func upstreamMessage(body io.Reader, status int) string {
	fallback := http.StatusText(status)
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBytes))
	if err != nil {
		return fallback
	}
	var parsed struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return fallback
	}
	var nested struct {
		Message string `json:"message"`
	}
	msg := ""
	if json.Unmarshal(parsed.Error, &nested) == nil {
		msg = nested.Message
	} else {
		_ = json.Unmarshal(parsed.Error, &msg)
	}
	if msg == "" {
		return fallback
	}
	if r := []rune(msg); len(r) > maxMessageLen {
		msg = string(r[:maxMessageLen])
	}
	return msg
}
