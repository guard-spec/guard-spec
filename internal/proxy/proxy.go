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
	"sync"
	"syscall"
	"time"

	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/giaplee/guard-spec/internal/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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
	// Propagate sends the W3C traceparent of the gateway's span upstream
	// (OTEL_PROPAGATE_UPSTREAM=true). Off by default: it would tell the
	// upstream the trace ID.
	Propagate bool
}

// Proxy sends requests to one upstream.
type Proxy struct {
	base      string
	key       string
	timeout   time.Duration
	propagate bool
	client    *http.Client
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

// maxBaseURL is the longest base URL ValidateBaseURL accepts.
const maxBaseURL = 2048

// deniedHosts are cloud metadata names. Their addresses are link-local, which
// the dialer refuses anyway; the names are refused early for a clear error.
var deniedHosts = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
	"metadata":                 true,
}

// ValidateBaseURL checks the base URL of an upstream an organization defines
// (the upstreams table). It applies the rules of New and also refuses
// credentials, a query or fragment, and addresses no LLM API lives at: cloud
// metadata names and link-local, multicast or unspecified IPs. The dialer
// refuses those addresses too, after DNS, so a name that resolves to one is
// refused when the gateway connects.
func ValidateBaseURL(raw string) error {
	if len(raw) > maxBaseURL {
		return fmt.Errorf("base_url is longer than %d bytes", maxBaseURL)
	}
	u, err := checkURL(raw)
	if err != nil {
		return err
	}
	if u.User != nil {
		return errors.New("base_url must not contain credentials; use api_key_env")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("base_url must not have a query or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if deniedHosts[host] {
		return fmt.Errorf("base_url host %s is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && deniedIP(ip) {
		return fmt.Errorf("base_url address %s is not allowed", host)
	}
	return nil
}

func checkURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("upstream url must be an absolute http or https url")
	}
	return u, nil
}

// deniedIP reports addresses the gateway never connects to: link-local (cloud
// metadata services live there), multicast and unspecified.
func deniedIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// dialControl refuses denied addresses after name resolution.
func dialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && deniedIP(ip) {
		return fmt.Errorf("upstream address %s is not allowed", host)
	}
	return nil
}

// New validates cfg and builds a Proxy.
func New(cfg Config) (*Proxy, error) {
	if _, err := checkURL(cfg.BaseURL); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Proxy{
		base:      strings.TrimRight(cfg.BaseURL, "/"),
		key:       cfg.Key,
		timeout:   cfg.Timeout,
		propagate: cfg.Propagate,
		client: &http.Client{
			// No client-wide Timeout: it would also cut off a long stream.
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: connectTimeout, Control: dialControl}).DialContext,
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
//
// path must come from the code, not the request: it is a metric label.
func (p *Proxy) Forward(ctx context.Context, path string, body []byte) (resp *Response, err error) {
	start := time.Now()
	ctx, end := tracing.Start(ctx, "upstream", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("upstream.path", path)))
	defer func() {
		outcome := "ok"
		if err != nil {
			outcome = "error"
			code := "upstream_unavailable"
			var e *Error
			if errors.As(err, &e) {
				code = e.Code
			}
			metrics.UpstreamErrors.WithLabelValues(path, code).Inc()
		}
		metrics.UpstreamDuration.WithLabelValues(path, outcome).Observe(time.Since(start).Seconds())
		end(err)
	}()
	return p.forward(ctx, path, body)
}

func (p *Proxy) forward(ctx context.Context, path string, body []byte) (*Response, error) {
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
	if p.propagate {
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
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

	body   io.ReadCloser
	cancel context.CancelFunc
	idle   time.Duration

	// The idle timer of a read is armed for one generation. A timer that fires
	// after its read returned, even by a hair, finds a newer generation or no
	// read in progress and does nothing, so it cannot kill a healthy stream.
	mu       sync.Mutex
	gen      uint64
	reading  bool
	timer    *time.Timer
	timedOut bool
}

// Stream reports whether the body is an event stream.
func (r *Response) Stream() bool {
	return strings.HasPrefix(strings.ToLower(r.ContentType), "text/event-stream")
}

// Read cancels the upstream if no data arrives for the configured timeout.
// The clock runs only during the read, so a slow client is not blamed on it.
func (r *Response) Read(p []byte) (int, error) {
	gen := r.arm()
	n, err := r.body.Read(p)
	timedOut := r.disarm(gen)
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}
	if timedOut {
		return n, timeoutError(err)
	}
	return n, classify(err)
}

// arm starts the idle clock for a new read and returns its generation.
func (r *Response) arm() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen++
	gen := r.gen
	r.reading = true
	r.timer = time.AfterFunc(r.idle, func() { r.expire(gen) })
	return gen
}

// disarm stops the clock of read gen and reports whether it had expired.
func (r *Response) disarm(gen uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gen == gen {
		r.reading = false
		if r.timer != nil {
			r.timer.Stop()
		}
	}
	return r.timedOut
}

// expire cancels the upstream only if read gen is still waiting for data.
func (r *Response) expire(gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.reading || r.gen != gen {
		return
	}
	r.timedOut = true
	r.cancel()
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
	r.mu.Lock()
	r.reading = false
	if r.timer != nil {
		r.timer.Stop()
	}
	r.mu.Unlock()
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
