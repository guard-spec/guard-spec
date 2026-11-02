package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/inference"
	"github.com/promptshield/promptshield/internal/policy"
	"github.com/promptshield/promptshield/internal/sanitizer"
	"github.com/promptshield/promptshield/internal/tenant"
)

const (
	injectionBlockThreshold = 0.85
	anomalyBlockThreshold   = 0.6
)

var (
	errBlocked            = errors.New("potential prompt injection detected")
	errUnsupportedContent = errors.New("unsupported content format")
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := loadConfig()

	runner, err := inference.NewRunner(cfg.ModelsPath)
	if err != nil {
		slog.Error("load models", "err", err)
		os.Exit(1)
	}

	engine, err := policy.New()
	if err != nil {
		slog.Error("init policy engine", "err", err)
		os.Exit(1)
	}

	var db *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		db, err = pgxpool.New(context.Background(), cfg.DatabaseURL)
		if err != nil || db.Ping(context.Background()) != nil {
			slog.Warn("gateway DB unavailable — request logging disabled", "err", err)
			db = nil
		} else {
			slog.Info("gateway DB connected — request logging enabled")
		}
	}

	app := newApp(runner, engine, db)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("gateway listening", "addr", cfg.ListenAddr)
		if err := app.Listen(cfg.ListenAddr); err != nil {
			slog.Error("listen", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = app.Shutdown()
}

// newApp builds the Fiber app with all gateway routes.
func newApp(runner *inference.Runner, engine *policy.Engine, db *pgxpool.Pool) *fiber.App {
	app := fiber.New(fiber.Config{
		ServerHeader: "promptshield",
	})

	app.Use(cors.New())

	// Health check — no auth required
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "version": "0.1.0"})
	})

	// All proxy routes require a valid API key.
	// During development, any non-empty key is accepted (stub lookup).
	app.Use(tenant.Middleware(stubKeyLookup))

	// OpenAI-compatible proxy
	app.Post("/v1/chat/completions", chatHandler(runner, engine))
	app.Post("/v1/completions", chatHandler(runner, engine))

	// Direct guardrail endpoints
	app.Post("/guardrail/scan", scanHandler(runner, engine, db))
	app.Post("/guardrail/sanitize", sanitizeHandler())

	return app
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func sanitizeHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Text string `json:"text"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if req.Text == "" {
			return c.Status(400).JSON(fiber.Map{"error": "text is required"})
		}

		cleaned, report, err := sanitizer.Sanitize(req.Text)
		if err != nil {
			return c.Status(422).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"text": cleaned, "report": report})
	}
}

func scanHandler(runner *inference.Runner, _ *policy.Engine, db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		var req struct {
			Text string `json:"text"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if req.Text == "" {
			return c.Status(400).JSON(fiber.Map{"error": "text is required"})
		}

		cleaned, report, err := sanitizer.Sanitize(req.Text)
		if err != nil {
			return c.Status(422).JSON(fiber.Map{"error": err.Error()})
		}

		scores, err := runner.Scan(c.Context(), cleaned)
		if err != nil {
			return scanError(c, err)
		}

		blocked := scores.Injection.Confidence >= injectionBlockThreshold ||
			report.AnomalyScore >= anomalyBlockThreshold
		action := "allow"
		if blocked {
			action = "block"
		}
		latencyMs := int(time.Since(start).Milliseconds())

		if db != nil {
			orgID, _ := tenant.OrgID(c)
			projID := tenant.ProjectID(c)
			go logRequest(db, orgID, projID, action, scores.Injection.Label, scores, report, latencyMs)
		}

		return c.JSON(fiber.Map{
			"injection_score": scores.Injection.Confidence,
			"injection_label": scores.Injection.Label,
			"toxicity_score":  scores.Toxicity.Confidence,
			"anomaly_score":   report.AnomalyScore,
			"had_tag_chars":   report.HadTagChars,
			"had_bidi":        report.HadBidi,
			"bytes_removed":   report.BytesRemoved,
			"sanitized_text":  cleaned,
			"blocked":         blocked,
		})
	}
}

func logRequest(db *pgxpool.Pool, orgID, projID uuid.UUID, action, injectionLabel string,
	scores inference.Scores, report sanitizer.Report, latencyMs int) {
	if orgID == uuid.Nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var label *string
	if injectionLabel != "" && injectionLabel != "BENIGN" {
		label = &injectionLabel
	}
	_, err := db.Exec(ctx,
		`INSERT INTO requests
		 (org_id, project_id, action, injection_label, injection_score, toxicity_score,
		  anomaly_score, had_tag_chars, had_bidi, latency_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		orgID,
		nullUUID(projID),
		action,
		label,
		scores.Injection.Confidence,
		scores.Toxicity.Confidence,
		report.AnomalyScore,
		report.HadTagChars,
		report.HadBidi,
		latencyMs,
	)
	if err != nil {
		slog.Warn("request log write failed", "err", err)
	}
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// scanError fails closed: a request we could not scan never reaches the upstream.
func scanError(c *fiber.Ctx, err error) error {
	if errors.Is(err, inference.ErrInputTooLong) {
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": err.Error()})
	}
	slog.Error("guardrail scan failed", "err", err)
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "guardrail unavailable"})
}

// textGuard sanitizes untrusted text in place and collects it for classification.
type textGuard struct {
	texts []string
}

func (g *textGuard) clean(text string) (string, error) {
	cleaned, rep, err := sanitizer.Sanitize(text)
	if err != nil {
		return "", err
	}
	// Block if anomaly score is high (tag chars = likely encoding attack)
	if rep.AnomalyScore >= anomalyBlockThreshold {
		slog.Info("blocked encoding attack", "score", rep.AnomalyScore, "had_tag_chars", rep.HadTagChars)
		return "", errBlocked
	}
	g.texts = append(g.texts, cleaned)
	return cleaned, nil
}

// guardContent handles the string and multi-part forms of a message's content.
func (g *textGuard) guardContent(m map[string]any) error {
	switch content := m["content"].(type) {
	case nil:
		return nil
	case string:
		cleaned, err := g.clean(content)
		if err != nil {
			return err
		}
		m["content"] = cleaned
		return nil
	case []any:
		for _, part := range content {
			p, ok := part.(map[string]any)
			if !ok {
				return errUnsupportedContent
			}
			if text, ok := p["text"].(string); ok {
				cleaned, err := g.clean(text)
				if err != nil {
					return err
				}
				p["text"] = cleaned
			}
		}
		return nil
	default:
		return errUnsupportedContent
	}
}

// guardMessages covers roles carrying untrusted text. System and assistant turns
// come from the integrating application and are left unchanged.
func (g *textGuard) guardMessages(raw any) error {
	if raw == nil {
		return nil
	}
	messages, ok := raw.([]any)
	if !ok {
		return errUnsupportedContent
	}
	for _, msg := range messages {
		m, ok := msg.(map[string]any)
		if !ok {
			return errUnsupportedContent
		}
		switch role, _ := m["role"].(string); role {
		case "system", "assistant":
		default:
			if err := g.guardContent(m); err != nil {
				return err
			}
		}
	}
	return nil
}

// guardPrompt handles the legacy completions field. Token arrays are refused
// because they cannot be scanned as text.
func (g *textGuard) guardPrompt(body map[string]any) error {
	switch prompt := body["prompt"].(type) {
	case nil:
		return nil
	case string:
		cleaned, err := g.clean(prompt)
		if err != nil {
			return err
		}
		body["prompt"] = cleaned
		return nil
	case []any:
		for i, item := range prompt {
			text, ok := item.(string)
			if !ok {
				return errUnsupportedContent
			}
			cleaned, err := g.clean(text)
			if err != nil {
				return err
			}
			prompt[i] = cleaned
		}
		return nil
	default:
		return errUnsupportedContent
	}
}

// guardError maps a sanitization failure to its HTTP response.
func guardError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errBlocked):
		return c.Status(200).JSON(blockedResponse("Request blocked: potential prompt injection detected."))
	case errors.Is(err, errUnsupportedContent):
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	default:
		return c.Status(422).JSON(fiber.Map{"error": "sanitize failed: " + err.Error()})
	}
}

// chatHandler is the OpenAI-compatible proxy entry point.
// It sanitizes the untrusted text, runs the guard pipeline, then proxies to the upstream.
func chatHandler(runner *inference.Runner, eng *policy.Engine) fiber.Handler {
	upstreamURL := os.Getenv("UPSTREAM_LLM_URL")
	upstreamKey := os.Getenv("UPSTREAM_LLM_KEY")

	return func(c *fiber.Ctx) error {
		// Parse request body
		var body map[string]any
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}

		// Extract + sanitize untrusted text
		var guard textGuard
		if err := guard.guardMessages(body["messages"]); err != nil {
			return guardError(c, err)
		}
		if err := guard.guardPrompt(body); err != nil {
			return guardError(c, err)
		}

		// Run injection classifier on all untrusted text combined
		if text := strings.Join(guard.texts, " "); text != "" {
			scores, err := runner.Scan(c.Context(), text)
			if err != nil {
				return scanError(c, err)
			}
			if scores.Injection.Confidence >= injectionBlockThreshold {
				slog.Info("blocked injection", "score", scores.Injection.Confidence)
				return c.Status(200).JSON(blockedResponse("Request blocked: prompt injection detected."))
			}
		}

		// No upstream configured — return stub response for development
		if upstreamURL == "" || upstreamKey == "" {
			return c.Status(200).JSON(fiber.Map{
				"id":      "chatcmpl-stub",
				"object": "chat.completion",
				"model":  body["model"],
				"choices": []fiber.Map{{
					"message": fiber.Map{
						"role":    "assistant",
						"content": "[guardrail passed — configure UPSTREAM_LLM_URL to proxy to a real model]",
					},
					"finish_reason": "stop",
					"index":         0,
				}},
			})
		}

		// Proxy to upstream (TODO: implement full streaming proxy)
		_ = upstreamURL
		_ = upstreamKey
		return c.Status(501).JSON(fiber.Map{"error": "upstream proxy not yet implemented"})
	}
}

func blockedResponse(reason string) fiber.Map {
	return fiber.Map{
		"id":     "chatcmpl-blocked",
		"object": "chat.completion",
		"choices": []fiber.Map{{
			"message": fiber.Map{
				"role":    "assistant",
				"content": reason,
			},
			"finish_reason": "content_filter",
			"index":         0,
		}},
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	ListenAddr  string
	ModelsPath  string
	DatabaseURL string
}

func loadConfig() config {
	return config{
		ListenAddr:  getenv("LISTEN_ADDR", ":8080"),
		ModelsPath:  getenv("MODELS_PATH", "./models"),
		DatabaseURL: getenv("DATABASE_URL", ""),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// stubKeyLookup accepts any non-empty key during development.
// Replace with a real Postgres lookup before production.
func stubKeyLookup(_ context.Context, keyHash string) (uuid.UUID, uuid.UUID, error) {
	if keyHash == "" {
		return uuid.Nil, uuid.Nil, nil
	}
	// Return a deterministic dev org ID so multi-tenant code can run
	devOrg := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	return devOrg, uuid.Nil, nil
}

