// Package metrics holds the Prometheus metrics of both binaries and serves
// them on their own listen address, away from the API port.
//
// Label values are bounded: routes, statuses, decisions, layers and kinds come
// from fixed sets in the code, never from the request. Org IDs appear only in
// the opt-in tenant metric (METRICS_TENANT_LABELS=true); API key IDs never do.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "guardspec"

// Registry holds every metric of this package plus the Go runtime and process
// collectors. A dedicated registry keeps dependencies' metrics out.
var Registry = prometheus.NewRegistry()

// latencyBuckets span sub-millisecond detector runs to multi-minute upstream
// calls.
var latencyBuckets = []float64{
	.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300,
}

var (
	// RequestsTotal counts gateway requests by route, HTTP status and decision.
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "requests_total",
		Help: "Gateway requests by route, status and decision (allow, block, error, output_leak, none).",
	}, []string{"route", "status", "decision"})

	// RequestDuration is the time from receipt until the response ends; for a
	// stream that is when the stream ends.
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "request_duration_seconds",
		Help:    "Gateway request latency by route, status and decision.",
		Buckets: latencyBuckets,
	}, []string{"route", "status", "decision"})

	// DetectorDuration is the time one detection layer takes on one chunk.
	DetectorDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "detector_duration_seconds",
		Help:    "Injection detector latency per layer (l1, l2, l3) and chunk.",
		Buckets: latencyBuckets,
	}, []string{"layer"})

	// DetectorErrors counts layers that failed and were left out of fusion.
	DetectorErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "detector_errors_total",
		Help: "Detection layer failures per layer.",
	}, []string{"layer"})

	// UpstreamDuration is the time until the upstream's response headers.
	UpstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "upstream_duration_seconds",
		Help:    "Time to the upstream's response headers, by path and outcome (ok or error).",
		Buckets: latencyBuckets,
	}, []string{"path", "outcome"})

	// UpstreamErrors counts upstream failures by the error code the client sees.
	UpstreamErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "upstream_errors_total",
		Help: "Upstream failures by path and code (upstream_timeout, upstream_unavailable, upstream_error, upstream_auth_failed).",
	}, []string{"path", "code"})

	// PolicyErrors counts requests refused with 503 because policies could not
	// be loaded or evaluated.
	PolicyErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "policy_eval_errors_total",
		Help: "Policy load, evaluation or upstream lookup failures (stage load, eval or route); each one fails the request closed.",
	}, []string{"stage"})

	// RouteSelections counts where chat requests that passed the guard were
	// sent. The upstream's name is not a label: names are per org and unbounded.
	RouteSelections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "route_selections_total",
		Help: "Upstream choice of allowed requests by source (rule, project, org, env, stub) and outcome " +
			"(ok, or failed: the target was missing, disabled or had no key, and the request failed closed).",
	}, []string{"source", "outcome"})

	// OutputActions counts what the output guard removed or caught, by kind.
	OutputActions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "output_guard_actions_total",
		Help: "Output guard actions by kind (image, link, url, canary, email, phone, cccd, card, ipv4).",
	}, []string{"kind"})

	// RateLimited counts requests refused with 429.
	RateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "ratelimit_rejections_total",
		Help: "Requests refused by the per-key rate limit, by the limit that refused them (requests or tokens).",
	}, []string{"limit"})

	// TenantRequests is registered only with METRICS_TENANT_LABELS=true.
	TenantRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "tenant_requests_total",
		Help: "Gateway requests by org and decision. Opt-in: one series per org.",
	}, []string{"org_id", "decision"})

	// HTTPRequests counts control plane requests.
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "control_plane", Name: "requests_total",
		Help: "Control plane requests by route pattern, method and status.",
	}, []string{"route", "method", "status"})

	// HTTPDuration is the control plane request latency.
	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "control_plane", Name: "request_duration_seconds",
		Help:    "Control plane request latency by route pattern, method and status.",
		Buckets: latencyBuckets,
	}, []string{"route", "method", "status"})

	// RetentionRuns counts retention runs (audit rows, activity log and
	// sessions in one pass) by result (ok, skipped, error).
	RetentionRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "audit_retention", Name: "runs_total",
		Help: "Retention runs (audit rows, activity log, sessions) by result: ok, skipped (another replica holds the lock) or error.",
	}, []string{"result"})

	// EventsDropped counts events the emitter dropped because its buffer was
	// full or the database refused the batch, by source (gateway, control_plane).
	EventsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_dropped_total",
		Help: "Alert events dropped (buffer full or write failed), by source.",
	}, []string{"source"})

	// EventsWritten counts events stored for the alert worker, by source.
	EventsWritten = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_written_total",
		Help: "Alert events written to the events table, by source.",
	}, []string{"source"})

	// AlertsFired counts alert notifications queued, by state (firing, resolved).
	AlertsFired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "alerts", Name: "notified_total",
		Help: "Alert notifications queued, by alert state (firing, resolved).",
	}, []string{"state"})

	// Deliveries counts delivery attempts by channel kind and result (sent,
	// retry, dead).
	Deliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "alerts", Name: "deliveries_total",
		Help: "Notification delivery attempts by channel kind and result (sent, retry, dead).",
	}, []string{"kind", "result"})

	// DeliveryLatency is the time from the event to the delivery attempt.
	DeliveryLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "alerts", Name: "delivery_latency_seconds",
		Help:    "Time from the newest event of an alert to its first delivery attempt, by channel kind.",
		Buckets: latencyBuckets,
	}, []string{"kind"})

	// RetentionDeleted counts audit rows deleted by retention.
	RetentionDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "audit_retention", Name: "deleted_rows_total",
		Help: "Audit rows deleted because they were older than AUDIT_RETENTION_DAYS.",
	}, []string{})

	// RetentionTableDeleted counts rows of other tables deleted by the same
	// retention job, by table (activity_log, sessions).
	RetentionTableDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "retention", Name: "deleted_rows_total",
		Help: "Rows deleted by retention by table: activity_log (ACTIVITY_LOG_RETENTION_DAYS), sessions (SESSION_RETENTION_DAYS) scan_cache (expired entries) or org_data_keys (retired content data keys no row uses).",
	}, []string{"table"})

	// ScanCacheLookups counts scan cache lookups per key, by layer (memory,
	// redis, postgres) and result (hit, miss, error). A key the memory layer
	// misses is looked up in the shared layer, when there is one.
	ScanCacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "scan_cache_lookups_total",
		Help: "Scan cache lookups per key by layer (memory, redis, postgres) and result (hit, miss, error).",
	}, []string{"layer", "result"})

	// ScanCacheErrors counts failed or timed-out calls to the shared scan
	// cache by layer and operation (get, set). The request is scanned anyway.
	ScanCacheErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "scan_cache_errors_total",
		Help: "Failed or timed-out shared scan cache calls by layer (redis, postgres) and operation (get, set); the request is scanned anyway.",
	}, []string{"layer", "op"})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		RequestsTotal, RequestDuration, DetectorDuration, DetectorErrors,
		UpstreamDuration, UpstreamErrors, PolicyErrors, RouteSelections, OutputActions, RateLimited,
		HTTPRequests, HTTPDuration, RetentionRuns, RetentionDeleted, RetentionTableDeleted,
		EventsDropped, EventsWritten, AlertsFired, Deliveries, DeliveryLatency,
		ScanCacheLookups, ScanCacheErrors, UnscannedParts,
		ScanWindows, ScanTokens, ScanQueueWait,
		PDFExtract, PDFExtractSeconds, PDFTextBytes,
	)
}

// The large-input lane: requests past the short path's limits, scanned on the
// long path when MAX_SCAN_TOKENS allows them (cmd/gateway/large_input.go).
var (
	// ScanWindows counts the token windows of long-path scans by result:
	// scored, duplicate (an identical window was scored) and skipped (the
	// text was already refused, early exit).
	ScanWindows = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "scan_windows_total",
		Help: "Token windows of long-path scans by result (scored, duplicate, skipped).",
	}, []string{"result"})

	// ScanTokens is the number of tokens each large-input request scanned.
	ScanTokens = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "scan_tokens",
		Help:    "Tokens scanned per large-input request (long path and short parts).",
		Buckets: prometheus.ExponentialBuckets(4096, 2, 10), // 4k to 2M
	})

	// ScanQueueWait is how long large-input requests waited for the lane, by
	// outcome: admitted, timeout (429 after LARGE_SCAN_QUEUE_TIMEOUT), full
	// (429 at once: the queue was full) and canceled (the wait was cut short).
	ScanQueueWait = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "scan_queue_wait_seconds",
		Help:    "Wait for the large-input lane by outcome (admitted, timeout, full, canceled).",
		Buckets: latencyBuckets,
	}, []string{"outcome"})
)

// UnscannedParts counts images, files and audio the gateway forwards (or
// refuses) without reading them, by kind and UNSCANNED_PARTS mode.
var UnscannedParts = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: namespace, Subsystem: "gateway", Name: "unscanned_parts_total",
	Help: "Request parts the detectors cannot read (image, file, audio, other), by kind and action (allow, log, block).",
}, []string{"kind", "action"})

// PDF text extraction (cmd/gateway/pdf_extract.go).
var (
	// PDFExtract counts the PDF parts of requests by outcome: ok (text
	// extracted and scanned), no_text, encrypted, damaged, timeout,
	// over_limit, internal (internal/pdftext), remote (a url or file id the
	// gateway cannot fetch) and busy (no extractor within
	// LARGE_SCAN_QUEUE_TIMEOUT: 429).
	PDFExtract = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "pdf_extract_total",
		Help: "PDF parts by extraction outcome (ok, no_text, encrypted, damaged, timeout, over_limit, internal, remote, busy).",
	}, []string{"result"})

	// PDFExtractSeconds is the time one extraction took, the wait for a
	// slot excluded.
	PDFExtractSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "pdf_extract_seconds",
		Help:    "Time to extract the text of one PDF part.",
		Buckets: latencyBuckets,
	})

	// PDFTextBytes is the size of the text extracted from one PDF part.
	PDFTextBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "pdf_text_bytes",
		Help:    "Bytes of text extracted from one PDF part.",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 8), // 1 KiB to 16 MiB
	})
)

var tenantLabels atomic.Bool

// EnableTenantLabels registers the per-org metric. Call it once at startup.
func EnableTenantLabels() {
	if tenantLabels.CompareAndSwap(false, true) {
		Registry.MustRegister(TenantRequests)
	}
}

// TenantLabels reports whether per-org series are on.
func TenantLabels() bool { return tenantLabels.Load() }

// Status renders an HTTP status as a label value.
func Status(code int) string {
	if code < 100 || code > 599 {
		return "other"
	}
	return strconv.Itoa(code)
}

// ObserveRequest records one finished gateway request.
func ObserveRequest(route string, status int, decision string, d time.Duration) {
	s := Status(status)
	RequestsTotal.WithLabelValues(route, s, decision).Inc()
	RequestDuration.WithLabelValues(route, s, decision).Observe(d.Seconds())
}

// Handler serves the registry in the Prometheus text format.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
}

// Serve listens on addr and serves /metrics until ctx ends. An empty addr or
// "off" serves nothing. Listen errors are returned before serving starts.
func Serve(ctx context.Context, addr string) error {
	if addr == "" || addr == "off" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", Handler())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	go func() {
		slog.Info("metrics listening", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server", "err", err)
		}
	}()
	return nil
}
