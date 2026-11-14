// Package proxy forwards sanitized requests to an upstream: an OpenAI-compatible
// API, or the Anthropic Messages API for /v1/messages.
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
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/tracing"
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
	BaseURL string // for example http://host:11434/v1
	Key     string // sent as a bearer token when set
	// KeyFunc, when set, is called for every request instead of Key, so a
	// key read from a file or Vault can change without a restart
	// (internal/secrets).
	KeyFunc func() string
	Timeout time.Duration // time to first byte, and longest silence after it
	// Propagate sends the W3C traceparent of the gateway's span upstream
	// (OTEL_PROPAGATE_UPSTREAM=true). Off by default: it would tell the
	// upstream the trace ID.
	Propagate bool
	// DenyPrivate refuses loopback, RFC 1918, unique local and CGNAT
	// addresses at dial time. The gateway sets it for org-defined upstreams
	// unless UPSTREAM_ALLOW_PRIVATE=true; UPSTREAM_LLM_URL is the operator's
	// and never has it.
	DenyPrivate bool
	// Headers are extra non-secret headers (upstreams.headers); invalid
	// ones are dropped.
	Headers map[string]string
	// KeyHeader sends Key in this header as is, instead of as a bearer
	// token in Authorization (Azure OpenAI: "api-key").
	KeyHeader string
	// APIVersion is added as ?api-version= to every request (Azure OpenAI).
	APIVersion string
	// Retries is how many times a request that failed before the upstream
	// answered (connection error or 5xx) is sent again, 0 to 3.
	Retries int
}

// Proxy sends requests to one upstream.
type Proxy struct {
	base       string
	key        string
	keyFunc    func() string
	keyHeader  string
	apiVersion string
	headers    map[string]string
	retries    int
	timeout    time.Duration
	propagate  bool
	client     *http.Client
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

// metadataIPs are cloud metadata services outside 169.254.0.0/16, which
// link-local already covers: AWS over IPv6, Alibaba Cloud, Oracle Cloud.
var metadataIPs = []net.IP{
	net.ParseIP("fd00:ec2::254"),
	net.ParseIP("100.100.100.200"),
	net.ParseIP("192.0.0.192"),
}

// cgnat is the shared address space of RFC 6598.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// deniedIP reports addresses the gateway never connects to: link-local and
// the other cloud metadata addresses, multicast and unspecified.
func deniedIP(ip net.IP) bool {
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// privateIP reports loopback, RFC 1918, unique local (fc00::/7) and CGNAT
// (100.64.0.0/10) addresses.
func privateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || cgnat.Contains(ip)
}

// ErrAddressNotAllowed matches (errors.Is) a dial the address rules refused.
var ErrAddressNotAllowed = errors.New("address not allowed")

// addressError is a refused dial; its text names the address, for operators.
type addressError struct{ host string }

func (e *addressError) Error() string {
	return fmt.Sprintf("upstream address %s is not allowed", e.host)
}

func (e *addressError) Is(target error) bool { return target == ErrAddressNotAllowed }

// dialControl refuses denied addresses after name resolution, and private
// ones too when denyPrivate is set.
func dialControl(denyPrivate bool) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil
		}
		if deniedIP(ip) || (denyPrivate && privateIP(ip)) {
			return &addressError{host: host}
		}
		return nil
	}
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
		base:       strings.TrimRight(cfg.BaseURL, "/"),
		key:        cfg.Key,
		keyFunc:    cfg.KeyFunc,
		keyHeader:  cfg.KeyHeader,
		apiVersion: cfg.APIVersion,
		headers:    safeHeaders(cfg.Headers),
		retries:    min(max(cfg.Retries, 0), 3),
		timeout:    cfg.Timeout,
		propagate:  cfg.Propagate,
		client: &http.Client{
			// No client-wide Timeout: it would also cut off a long stream.
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: connectTimeout, Control: dialControl(cfg.DenyPrivate)}).DialContext,
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
func (p *Proxy) Forward(ctx context.Context, path string, body []byte) (*Response, error) {
	return p.Do(ctx, path, body, Call{})
}

// backendPathRe and backendQueryRe bound Call.URLPath and Call.RawQuery:
// printable ASCII without spaces or a fragment, the path absolute and
// without a query or backslash, so neither can change the URL's host.
var (
	backendPathRe  = regexp.MustCompile(`^/[!-"$-/0-9:-;=>@-\[\]-~]*$`)
	backendQueryRe = regexp.MustCompile(`^[!-"$-~]*$`)
)

// Call holds the settings of one request that differ from the proxy's.
type Call struct {
	// Method is the HTTP method; "" is POST. A GET sends no body.
	Method string
	// KeyHeader sends the key in this header as is for this request, instead
	// of the proxy's (the Anthropic Messages API: "x-api-key").
	KeyHeader string
	// Header holds headers the gateway takes from the client after checking
	// them (anthropic-version, anthropic-beta). Reserved and credential names
	// are dropped, and the upstream's configured headers and the credentials
	// win over them.
	Header http.Header

	// For a custom backend (the gateway's /v1/backend): URLPath, when set,
	// is appended to the base URL instead of the path argument, which stays
	// the metric label; RawQuery is added after it as is; ContentType is
	// sent instead of application/json; an empty body is not sent at all.
	URLPath     string
	RawQuery    string
	ContentType string
	// PassClientErrors returns a 4xx answer as a Response, for the caller
	// to relay, except 401 and 407, which are about the gateway's own
	// credentials and stay an *Error.
	PassClientErrors bool
}

// Do sends a request to base+path with the settings of call. Like Forward, it
// builds the request from scratch: only call.Header reaches the upstream from
// the client, and the caller decides what goes in it.
//
// path must come from the code, not the request: it is a metric label.
func (p *Proxy) Do(ctx context.Context, path string, body []byte, call Call) (resp *Response, err error) {
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
	return p.forward(ctx, path, body, call)
}

// url is base+path with the api-version query when one is set.
func (p *Proxy) url(path string) string {
	if p.apiVersion == "" {
		return p.base + path
	}
	return p.base + path + "?api-version=" + url.QueryEscape(p.apiVersion)
}

// setHeaders sets the configured extra headers, then the credentials, so
// that no extra header can replace them.
func (p *Proxy) setHeaders(req *http.Request) {
	p.setCallHeaders(req, Call{})
}

// setCallHeaders sets the call's headers, then the configured extra headers,
// then the credentials: nothing set earlier can replace what comes after it.
func (p *Proxy) setCallHeaders(req *http.Request, call Call) {
	req.Header.Set("User-Agent", "") // keep Go's default out
	for k, values := range call.Header {
		if !callHeaderAllowed(k) {
			continue
		}
		for _, v := range values {
			if strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0 {
				req.Header.Add(k, v)
			}
		}
	}
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}
	key := p.key
	if p.keyFunc != nil {
		key = p.keyFunc()
	}
	if key != "" {
		keyHeader := p.keyHeader
		if call.KeyHeader != "" {
			keyHeader = call.KeyHeader
		}
		if keyHeader != "" {
			req.Header.Set(keyHeader, key)
		} else {
			req.Header.Set("Authorization", "Bearer "+key)
		}
	}
}

// callHeaderAllowed refuses names the gateway or the transport sets, and any
// that could carry a credential.
func callHeaderAllowed(name string) bool {
	lower := strings.ToLower(name)
	if !headerNameRe.MatchString(name) || reservedHeaders[lower] || strings.HasPrefix(lower, "x-forwarded-") ||
		strings.HasPrefix(lower, "proxy-") {
		return false
	}
	for _, w := range secretNameWords {
		if strings.Contains(lower, w) {
			return false
		}
	}
	return true
}

// retryable reports a failure the upstream did not answer, or answered with
// a 5xx: sending the same body again is safe.
func retryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == "upstream_unavailable" || (e.Code == "upstream_error" && e.Status == http.StatusBadGateway &&
		e.Message == "upstream error")
}

func (p *Proxy) forward(ctx context.Context, path string, body []byte, call Call) (*Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := p.forwardOnce(ctx, path, body, call)
		if err == nil || attempt >= p.retries || !retryable(err) || ctx.Err() != nil {
			return resp, err
		}
		slog.Warn("upstream request failed, retrying", "attempt", attempt+1, "err", err)
	}
}

func (p *Proxy) forwardOnce(ctx context.Context, path string, body []byte, call Call) (*Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	method := http.MethodPost
	if call.Method != "" {
		method = call.Method
	}
	var reader io.Reader
	if method != http.MethodGet && (call.URLPath == "" || len(body) > 0) {
		reader = bytes.NewReader(body)
	}
	target := p.url(path)
	if call.URLPath != "" {
		// The caller checked the path (backend.CleanPath and the prefixes);
		// this is the last line: only a path and a query that cannot leave
		// the base URL's host reach the URL.
		if !backendPathRe.MatchString(call.URLPath) || !backendQueryRe.MatchString(call.RawQuery) {
			cancel()
			return nil, &Error{Status: http.StatusBadRequest, Code: "invalid_path", Message: "invalid backend path or query"}
		}
		target = p.base + call.URLPath
		if call.RawQuery != "" {
			target += "?" + call.RawQuery
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		cancel()
		return nil, classify(err)
	}
	p.setCallHeaders(req, call)
	if reader != nil {
		contentType := "application/json"
		if call.ContentType != "" {
			contentType = call.ContentType
		}
		req.Header.Set("Content-Type", contentType)
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
		Header:      resp.Header,
		body:        resp.Body,
		cancel:      cancel,
		idle:        p.timeout,
	}

	if call.PassClientErrors && resp.StatusCode >= 400 && resp.StatusCode <= 499 &&
		resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusProxyAuthRequired {
		return r, nil
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
	// Header is the upstream's response headers; the caller picks what it
	// relays.
	Header http.Header

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

// upstreamMessage reads the OpenAI error shape (Anthropic's error object has
// a message too), or the flat one some servers use.
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
