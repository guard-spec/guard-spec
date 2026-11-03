// Package tracing sets up optional OpenTelemetry tracing.
//
// Tracing is off unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Spans are then
// exported over OTLP/HTTP; the exporter reads the standard OTEL_EXPORTER_OTLP_*
// variables (headers, timeout, TLS). OTLP/gRPC is not supported. While off,
// the global no-op provider makes every span free.
package tracing

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0" // must match the SDK's, or resource.Merge fails
	"go.opentelemetry.io/otel/trace"
)

const instrumentation = "github.com/giaplee/guard-spec"

// Enabled reports whether the environment asks for tracing.
func Enabled() bool {
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" ||
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) != ""
}

// Setup installs the global tracer provider and the W3C trace context
// propagator when tracing is enabled. The returned function flushes and stops
// the exporter; it is a no-op when tracing is off.
func Setup(ctx context.Context, service string) (shutdown func(context.Context) error, err error) {
	if !Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(service)))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp.Shutdown, nil
}

// Tracer returns the tracer of this module.
func Tracer() trace.Tracer { return otel.Tracer(instrumentation) }

// Start begins a span. end records err, if any, and ends the span.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, func(err error)) {
	ctx, span := Tracer().Start(ctx, name, opts...)
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}
