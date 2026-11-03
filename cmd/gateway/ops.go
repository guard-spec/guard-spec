package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/giaplee/guard-spec/internal/ratelimit"
	"github.com/giaplee/guard-spec/internal/tracing"
)

// opsConfig is the observability and rate limit configuration.
type opsConfig struct {
	MetricsAddr  string // METRICS_ADDR; "off" disables the metrics listener
	TenantLabels bool   // METRICS_TENANT_LABELS: per-org series
	Propagate    bool   // OTEL_PROPAGATE_UPSTREAM: send traceparent upstream
	RateLimit    ratelimit.Limits
}

func loadOpsConfig(env func(string) string) (opsConfig, error) {
	get := func(key, fallback string) string {
		if v := strings.TrimSpace(env(key)); v != "" {
			return v
		}
		return fallback
	}
	cfg := opsConfig{MetricsAddr: get("METRICS_ADDR", ":9090")}
	var err error
	if cfg.TenantLabels, err = strconv.ParseBool(get("METRICS_TENANT_LABELS", "false")); err != nil {
		return cfg, fmt.Errorf("METRICS_TENANT_LABELS must be true or false: %w", err)
	}
	if cfg.Propagate, err = strconv.ParseBool(get("OTEL_PROPAGATE_UPSTREAM", "false")); err != nil {
		return cfg, fmt.Errorf("OTEL_PROPAGATE_UPSTREAM must be true or false: %w", err)
	}
	for _, v := range []struct {
		key string
		dst *int64
	}{{"RATE_LIMIT_RPM", &cfg.RateLimit.RPM}, {"RATE_LIMIT_TPM", &cfg.RateLimit.TPM}} {
		n, err := strconv.ParseInt(get(v.key, "0"), 10, 64)
		if err != nil || n < 0 {
			return cfg, fmt.Errorf("%s must be a whole number, 0 or more (0 = unlimited)", v.key)
		}
		*v.dst = n
	}
	return cfg, nil
}

// startOps starts the metrics listener and tracing. The returned function
// flushes pending spans; call it on shutdown.
func startOps(ctx context.Context, cfg opsConfig) (func(), error) {
	if cfg.TenantLabels {
		metrics.EnableTenantLabels()
	}
	if err := metrics.Serve(ctx, cfg.MetricsAddr); err != nil {
		return nil, fmt.Errorf("metrics listener %s: %w", cfg.MetricsAddr, err)
	}
	shutdown, err := tracing.Setup(ctx, "guard-spec-gateway")
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}
	slog.Info("observability", "metrics_addr", cfg.MetricsAddr, "tracing", tracing.Enabled(),
		"propagate_upstream", cfg.Propagate, "rate_limit_rpm", cfg.RateLimit.RPM, "rate_limit_tpm", cfg.RateLimit.TPM)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			slog.Warn("tracing shutdown", "err", err)
		}
	}, nil
}
