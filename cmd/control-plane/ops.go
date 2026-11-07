package main

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/retention"
)

// opsConfig is the metrics and retention (audit rows, activity log,
// sessions) configuration.
type opsConfig struct {
	MetricsAddr string // METRICS_ADDR; "off" disables the metrics listener
	Retention   retention.Config
}

func loadOpsConfig(env func(string) string) (opsConfig, error) {
	get := func(key, fallback string) string {
		if v := strings.TrimSpace(env(key)); v != "" {
			return v
		}
		return fallback
	}
	cfg := opsConfig{MetricsAddr: get("METRICS_ADDR", ":9091")}
	days, err := strconv.Atoi(get("AUDIT_RETENTION_DAYS", "90"))
	if err != nil || days < 0 {
		return cfg, errors.New("AUDIT_RETENTION_DAYS must be a whole number of days, 0 or more (0 = keep forever)")
	}
	interval, err := time.ParseDuration(get("AUDIT_RETENTION_INTERVAL", "1h"))
	if err != nil || interval < time.Minute {
		return cfg, errors.New("AUDIT_RETENTION_INTERVAL must be a duration of at least 1m, such as 1h")
	}
	batch, err := strconv.Atoi(get("AUDIT_RETENTION_BATCH", "5000"))
	if err != nil || batch < 1 || batch > 100000 {
		return cfg, errors.New("AUDIT_RETENTION_BATCH must be between 1 and 100000")
	}
	activityDays, err := strconv.Atoi(get("ACTIVITY_LOG_RETENTION_DAYS", "365"))
	if err != nil || activityDays < 0 {
		return cfg, errors.New("ACTIVITY_LOG_RETENTION_DAYS must be a whole number of days, 0 or more (0 = keep forever)")
	}
	sessionDays, err := strconv.Atoi(get("SESSION_RETENTION_DAYS", "30"))
	if err != nil || sessionDays < 0 {
		return cfg, errors.New("SESSION_RETENTION_DAYS must be a whole number of days, 0 or more (0 = keep forever)")
	}
	cfg.Retention = retention.Config{
		Days: days, ActivityDays: activityDays, SessionDays: sessionDays,
		Interval: interval, Batch: batch,
		// The shared scan cache (migration 020) has its own expiry; its
		// expired rows go whatever the retention periods are.
		ScanCache: true,
	}
	return cfg, nil
}

// observe records control plane request metrics. The route label is the
// matched route pattern (such as /v1/organizations/:orgId/invites), never the
// raw path, so org IDs stay out of it.
func observe() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		status := c.Response().StatusCode()
		if err != nil {
			status = fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				status = fe.Code
			}
		}
		route := "other"
		if r := c.Route(); r != nil && r.Path != "" && r.Path != "/" {
			route = r.Path // a pattern from the code; a copy, not fiber's buffer
		}
		method := "other"
		switch m := c.Method(); m {
		case fiber.MethodGet, fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
			method = strings.Clone(m)
		}
		s := metrics.Status(status)
		metrics.HTTPRequests.WithLabelValues(route, method, s).Inc()
		metrics.HTTPDuration.WithLabelValues(route, method, s).Observe(time.Since(start).Seconds())
		return err
	}
}
