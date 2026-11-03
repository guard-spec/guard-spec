package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/promptshield/promptshield/internal/metrics"
	"github.com/promptshield/promptshield/internal/proxy"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestRequestMetrics(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, nil)
	allow := metrics.RequestsTotal.WithLabelValues("/v1/chat/completions", "200", "allow")
	block := metrics.RequestsTotal.WithLabelValues("/v1/chat/completions", "400", "block")
	unauth := metrics.RequestsTotal.WithLabelValues("/v1/chat/completions", "401", "none")
	a0, b0, u0 := counterValue(t, allow), counterValue(t, block), counterValue(t, unauth)

	h.post(t, "/v1/chat/completions", clean, nil)
	h.post(t, "/v1/chat/completions", attackBody, nil)
	h.post(t, "/v1/chat/completions", clean, map[string]string{"x-api-key": "wrong"})

	if d := counterValue(t, allow) - a0; d != 1 {
		t.Errorf("allow delta = %v, want 1", d)
	}
	if d := counterValue(t, block) - b0; d != 1 {
		t.Errorf("block delta = %v, want 1", d)
	}
	if d := counterValue(t, unauth) - u0; d != 1 {
		t.Errorf("unauthenticated delta = %v, want 1", d)
	}

	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`guardspec_gateway_requests_total{decision="allow",route="/v1/chat/completions",status="200"}`,
		`guardspec_gateway_request_duration_seconds_bucket{decision="block"`,
		`guardspec_gateway_detector_duration_seconds_count{layer="l1"}`,
		`guardspec_gateway_upstream_duration_seconds_count{outcome="ok",path="/chat/completions"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics lacks %s", want)
		}
	}
	// Bounded labels: no tenant or key identifiers unless opted in.
	for _, banned := range []string{"org_id", devOrg.String(), "api_key", "test"} {
		if strings.Contains(out, banned+"=") || strings.Contains(out, `"`+banned+`"`) {
			t.Errorf("/metrics contains %q", banned)
		}
	}
}

func TestUnknownRouteIsOther(t *testing.T) {
	if got := routeLabel("/v1/chat/completions/" + strings.Repeat("x", 10)); got != "other" {
		t.Errorf("routeLabel = %q", got)
	}
}

func TestMetricsServer(t *testing.T) {
	ctx := t.Context()
	if err := metrics.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := metrics.Serve(ctx, "off"); err != nil {
		t.Fatal(err)
	}
}

// withSpanRecorder installs a recording tracer provider for one test.
func withSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
	return sr
}

const clientTrace = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestTracingSpansAndPropagation(t *testing.T) {
	for _, propagate := range []bool{false, true} {
		sr := withSpanRecorder(t)
		up := newFakeUpstream(t, okUpstream)
		h := startGateway(t, "", func(gw *gateway) {
			var err error
			gw.upstream, err = proxy.New(proxy.Config{BaseURL: up.URL + "/v1", Timeout: 30 * time.Second,
				Propagate: propagate})
			if err != nil {
				t.Fatal(err)
			}
		})
		resp, body := h.post(t, "/v1/chat/completions", clean, map[string]string{"traceparent": clientTrace})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		names := map[string]bool{}
		for _, s := range sr.Ended() {
			names[s.Name()] = true
			if got := s.SpanContext().TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
				t.Errorf("span %s has trace %s, want the client's", s.Name(), got)
			}
		}
		for _, want := range []string{"POST /v1/chat/completions", "sanitize", "detect", "policy", "upstream", "output_guard"} {
			if !names[want] {
				t.Errorf("propagate=%v: no %q span; got %v", propagate, want, names)
			}
		}
		up.mu.Lock()
		tp := up.headers.Get("Traceparent")
		up.mu.Unlock()
		switch {
		case propagate && !strings.Contains(tp, "0af7651916cd43dd8448eb211c80319c"):
			t.Errorf("traceparent upstream = %q, want the trace propagated", tp)
		case !propagate && tp != "":
			t.Errorf("traceparent upstream = %q, want none", tp)
		}
	}
}

func TestTracingOffByDefault(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	stop, err := startOps(t.Context(), opsConfig{MetricsAddr: "off"})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	// Without a provider, a client's traceparent is not forwarded either.
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, "", func(gw *gateway) {
		gw.upstream, _ = proxy.New(proxy.Config{BaseURL: up.URL + "/v1", Propagate: true})
	})
	resp, _ := h.post(t, "/v1/chat/completions", clean, map[string]string{"traceparent": clientTrace})
	_, _ = io.Copy(io.Discard, resp.Body)
	up.mu.Lock()
	defer up.mu.Unlock()
	if tp := up.headers.Get("Traceparent"); tp != "" {
		t.Errorf("traceparent upstream = %q with tracing off", tp)
	}
}
