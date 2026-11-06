package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// decisionNone labels a request that ended before the guard decided anything:
// no API key, rate limited, a bad body on the sanitize endpoint.
const decisionNone = "none"

// auditedKey marks a request whose audit row records its metrics (see
// observeEntry), so that observe does not count it a second time.
const auditedKey = "guardspec_audited"

// knownRoutes bounds the route label; anything else is "other".
var knownRoutes = map[string]string{}

func init() {
	for _, r := range []string{"/health", "/readyz", "/v1/chat/completions", "/v1/completions",
		"/v1/messages", "/v1/messages/count_tokens", "/v1/models",
		"/guardrail/scan", "/guardrail/sanitize"} {
		knownRoutes[r] = r
	}
}

// routeLabel returns a constant string, never path itself: fiber reuses the
// buffer behind c.Path() once the handler returns.
func routeLabel(path string) string {
	if r, ok := knownRoutes[path]; ok {
		return r
	}
	return "other"
}

// observe starts the request span and records metrics for requests that write
// no audit row. Audited requests are recorded by observeEntry, which knows the
// decision and, for a stream, when it ended.
func observe() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		route := routeLabel(c.Path())
		var span trace.Span
		if route != "/health" && route != "/readyz" {
			// Copies: fiber's strings point into buffers it reuses, and spans
			// are exported after the handler returns.
			carrier := propagation.MapCarrier{}
			for _, h := range []string{"traceparent", "tracestate"} {
				if v := c.Get(h); v != "" {
					carrier[h] = strings.Clone(v)
				}
			}
			method := strings.Clone(c.Method())
			ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
			ctx, span = tracing.Tracer().Start(ctx, method+" "+route,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(attribute.String("http.route", route),
					attribute.String("http.request.method", method)))
			c.SetUserContext(ctx)
		}

		err := c.Next()

		status := c.Response().StatusCode()
		if err != nil {
			status = fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				status = fe.Code
			}
		}
		if span != nil {
			span.SetAttributes(attribute.Int("http.response.status_code", status))
			span.End()
		}
		if audited, _ := c.Locals(auditedKey).(bool); !audited {
			metrics.ObserveRequest(route, status, decisionNone, time.Since(start))
		}
		return err
	}
}

// requestContext is base carrying the request's span, so that pipeline spans
// become its children while cancellation still follows base. It is safe to
// keep after the handler returns.
func requestContext(c *fiber.Ctx, base context.Context) context.Context {
	return trace.ContextWithSpan(base, trace.SpanFromContext(c.UserContext()))
}

// observeEntry records the metrics of a request with an audit row.
func observeEntry(e requestEntry) {
	decision := e.Action
	switch decision {
	case actionAllow, actionRoute, actionBlock, actionError, actionOutputLeak:
	default:
		decision = "other"
	}
	var d time.Duration
	if !e.Start.IsZero() {
		d = time.Since(e.Start)
	}
	metrics.ObserveRequest(routeLabel(e.Route), e.Status, decision, d)
	for kind, n := range e.Output {
		if n > 0 {
			metrics.OutputActions.WithLabelValues(outputKindLabel(kind)).Add(float64(n))
		}
	}
	if metrics.TenantLabels() && e.OrgID != uuid.Nil {
		metrics.TenantRequests.WithLabelValues(e.OrgID.String(), decision).Inc()
	}
}

func outputKindLabel(kind string) string {
	switch kind {
	case outputguard.KindImage, outputguard.KindLink, outputguard.KindURL, outputguard.KindCanary,
		outputguard.KindEmail, outputguard.KindPhone, outputguard.KindCCCD, outputguard.KindCard, outputguard.KindIPv4:
		return kind
	}
	return "other"
}
