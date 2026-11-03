package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/inference"
	"github.com/promptshield/promptshield/internal/policy"
	"github.com/promptshield/promptshield/internal/proxy"
	"github.com/promptshield/promptshield/internal/sanitizer"
	"github.com/promptshield/promptshield/internal/tenant"
)

const (
	injectionBlockThreshold = 0.85
	anomalyBlockThreshold   = 0.6

	// policyTimeout bounds loading and evaluating one request's policies.
	policyTimeout = 5 * time.Second
	// shutdownGrace is how long open streams get before they are cancelled.
	shutdownGrace = 5 * time.Second

	// Values of requests.action. A log rule is recorded as allow with its rule_id,
	// and anything refused as block, because the column documents no other value.
	actionAllow = "allow"
	actionBlock = "block"
)

var (
	errBlocked            = errors.New("potential prompt injection detected")
	errUnsupportedContent = errors.New("unsupported content format")
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	var upstream *proxy.Proxy
	if cfg.UpstreamURL != "" {
		upstream, err = proxy.New(proxy.Config{
			BaseURL: cfg.UpstreamURL,
			Key:     cfg.UpstreamKey,
			Timeout: cfg.UpstreamTimeout,
		})
		if err != nil {
			slog.Error("upstream config", "err", err)
			os.Exit(1)
		}
	}

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

	db, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err == nil {
		err = db.Ping(context.Background())
	}
	if err != nil {
		slog.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	base, cancelUpstream := context.WithCancel(context.Background())
	defer cancelUpstream()

	audit := newAuditLog(func(e requestEntry) { logRequest(db, e) })
	app := newApp(gateway{
		runner:   runner,
		engine:   engine,
		policies: dbPolicyLoader(db),
		audit:    audit,
		upstream: upstream,
		base:     base,
	}, dbKeyLookup(db))

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
	_ = app.ShutdownWithTimeout(shutdownGrace)
	cancelUpstream()
	audit.wait() // the pool closes after this; pending rows need it
}

// policyLoader returns the enabled policies for a request, in evaluation order.
type policyLoader func(ctx context.Context, orgID, projectID uuid.UUID) ([]policy.Policy, error)

// gateway holds what the handlers depend on. A nil upstream means stub responses.
type gateway struct {
	runner   *inference.Runner
	engine   *policy.Engine
	policies policyLoader
	audit    *auditLog
	upstream *proxy.Proxy
	base     context.Context // parent of upstream calls; a fiber ctx dies with the handler
}

// newApp builds the Fiber app with all gateway routes.
func newApp(gw gateway, lookup tenant.LookupFn) *fiber.App {
	app := fiber.New(fiber.Config{
		ServerHeader: "promptshield",
	})

	app.Use(cors.New())

	// Health check — no auth required
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "version": "0.1.0"})
	})

	// All proxy routes require a valid API key.
	app.Use(tenant.Middleware(lookup))

	// OpenAI-compatible proxy
	app.Post("/v1/chat/completions", chatHandler(gw, "/chat/completions"))
	app.Post("/v1/completions", chatHandler(gw, "/completions"))

	// Direct guardrail endpoints
	app.Post("/guardrail/scan", scanHandler(gw))
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

func scanHandler(gw gateway) fiber.Handler {
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

		scores, err := gw.runner.Scan(c.Context(), cleaned)
		if err != nil {
			return scanError(c, err)
		}

		blocked := scores.Injection.Confidence >= injectionBlockThreshold ||
			report.AnomalyScore >= anomalyBlockThreshold
		entry := newEntry(c)
		entry.Action = actionAllow
		if blocked {
			entry.Action = actionBlock
		}
		entry.Scores = scores
		entry.Report = report
		entry.LatencyMs = int(time.Since(start).Milliseconds())
		gw.audit.record(entry)

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

// requestEntry is one row of the requests table.
type requestEntry struct {
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	Model     string
	Action    string
	RuleID    uuid.UUID
	Scores    inference.Scores
	Report    sanitizer.Report
	LatencyMs int
}

// newEntry starts a row for the caller. Handlers must copy what they need from
// c before going async, because fiber reuses it once the handler returns.
func newEntry(c *fiber.Ctx) requestEntry {
	orgID, _ := tenant.OrgID(c)
	return requestEntry{OrgID: orgID, ProjectID: tenant.ProjectID(c), Action: actionBlock}
}

// auditLog writes rows without delaying the response, and tracks them so that
// shutdown can wait for those still in flight.
type auditLog struct {
	write func(requestEntry)
	wg    sync.WaitGroup
}

func newAuditLog(write func(requestEntry)) *auditLog {
	return &auditLog{write: write}
}

func (a *auditLog) record(e requestEntry) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.write(e)
	}()
}

func (a *auditLog) wait() { a.wg.Wait() }

func logRequest(db *pgxpool.Pool, e requestEntry) {
	if e.OrgID == uuid.Nil {
		slog.Warn("request log skipped: no org")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var label, model *string
	if l := e.Scores.Injection.Label; l != "" && l != "BENIGN" {
		label = &l
	}
	if e.Model != "" {
		model = &e.Model
	}
	err := tenant.WithOrg(ctx, db, e.OrgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO requests
			 (org_id, project_id, model, action, rule_id, injection_label, injection_score,
			  toxicity_score, anomaly_score, had_tag_chars, had_bidi, latency_ms)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			e.OrgID,
			nullUUID(e.ProjectID),
			model,
			e.Action,
			nullUUID(e.RuleID),
			label,
			e.Scores.Injection.Confidence,
			e.Scores.Toxicity.Confidence,
			e.Report.AnomalyScore,
			e.Report.HadTagChars,
			e.Report.HadBidi,
			e.LatencyMs,
		)
		return err
	})
	if err != nil {
		slog.Warn("request log write failed", "err", err, "action", e.Action)
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
	texts  []string
	report sanitizer.Report // worst signals across all texts, for the audit log
}

func (g *textGuard) merge(rep sanitizer.Report) {
	g.report.HadTagChars = g.report.HadTagChars || rep.HadTagChars
	g.report.HadBidi = g.report.HadBidi || rep.HadBidi
	if rep.AnomalyScore > g.report.AnomalyScore {
		g.report.AnomalyScore = rep.AnomalyScore
	}
}

func (g *textGuard) clean(text string) (string, error) {
	cleaned, rep, err := sanitizer.Sanitize(text)
	if err != nil {
		return "", err
	}
	g.merge(rep)
	// Block if anomaly score is high (tag chars = likely encoding attack)
	if rep.AnomalyScore >= anomalyBlockThreshold {
		slog.Info("blocked encoding attack", "score", rep.AnomalyScore, "had_tag_chars", rep.HadTagChars)
		return "", errBlocked
	}
	g.texts = append(g.texts, cleaned)
	return cleaned, nil
}

// rejectShadowKeys refuses a key that differs from a guarded one only in case.
// Go-based upstreams such as Ollama match JSON keys case-insensitively, so they
// would read "Content" as the text this guard never saw.
func rejectShadowKeys(m map[string]any, guarded ...string) error {
	for key := range m {
		for _, name := range guarded {
			if key != name && strings.EqualFold(key, name) {
				return errUnsupportedContent
			}
		}
	}
	return nil
}

// guardBody sanitizes every untrusted text field of a chat or completion request.
func (g *textGuard) guardBody(body map[string]any) error {
	if err := rejectShadowKeys(body, "messages", "prompt", "suffix"); err != nil {
		return err
	}
	if err := g.guardMessages(body["messages"]); err != nil {
		return err
	}
	if err := g.guardPrompt(body); err != nil {
		return err
	}
	return g.guardSuffix(body)
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
			if err := rejectShadowKeys(p, "text"); err != nil {
				return err
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
		if err := rejectShadowKeys(m, "role", "content"); err != nil {
			return err
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

// guardSuffix handles the text a legacy completion appends after the output.
func (g *textGuard) guardSuffix(body map[string]any) error {
	switch suffix := body["suffix"].(type) {
	case nil:
		return nil
	case string:
		cleaned, err := g.clean(suffix)
		if err != nil {
			return err
		}
		body["suffix"] = cleaned
		return nil
	default:
		return errUnsupportedContent
	}
}

// guardError maps a sanitization failure to its HTTP response.
func guardError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errBlocked):
		return blockResponse(c, "Request blocked: potential prompt injection detected.")
	case errors.Is(err, errUnsupportedContent):
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	default:
		return c.Status(422).JSON(fiber.Map{"error": "sanitize failed: " + err.Error()})
	}
}

// decodeBody keeps numbers exact, so a large seed is not rounded on its way upstream.
func decodeBody(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	if body == nil {
		return nil, errors.New("body is not an object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after body")
	}
	return body, nil
}

// chatHandler is the OpenAI-compatible proxy entry point.
// It sanitizes the untrusted text, applies the fixed thresholds and the org's
// policies, then proxies the sanitized body to upstreamPath. Every request gets
// one audit row: refused unless it reaches the point where entry.Action is set.
func chatHandler(gw gateway, upstreamPath string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		entry := newEntry(c)
		streaming := false // the stream writes the row when it ends
		defer func() {
			if !streaming {
				entry.LatencyMs = int(time.Since(start).Milliseconds())
				gw.audit.record(entry)
			}
		}()

		// Parse request body
		body, err := decodeBody(c.Body())
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		entry.Model, _ = body["model"].(string)

		// Extract + sanitize untrusted text
		var guard textGuard
		err = guard.guardBody(body)
		entry.Report = guard.report
		if err != nil {
			return guardError(c, err)
		}

		// Run injection classifier on all untrusted text combined
		if text := strings.Join(guard.texts, " "); text != "" {
			scores, err := gw.runner.Scan(c.Context(), text)
			if err != nil {
				return scanError(c, err)
			}
			entry.Scores = scores
			if scores.Injection.Confidence >= injectionBlockThreshold {
				slog.Info("blocked injection", "score", scores.Injection.Confidence)
				return blockResponse(c, "Request blocked: prompt injection detected.")
			}
		}

		sanitized, err := json.Marshal(body)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}

		// Policies run after the fixed thresholds, so they can only tighten them.
		decision, err := gw.evaluatePolicies(entry, policyVars(entry, body, len(sanitized)))
		if err != nil {
			slog.Error("policy evaluation failed", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		entry.RuleID = decision.RuleID
		switch decision.Action {
		case policy.ActionAllow, policy.ActionLog:
		case policy.ActionBlock:
			slog.Info("blocked by policy", "rule", decision.RuleID)
			return blockResponse(c, "Request blocked by policy.")
		default:
			// redact and route are refused when saved, so this is a stale rule.
			slog.Error("rule has an action the gateway cannot enforce",
				"rule", decision.RuleID, "action", decision.Action)
			return policyUnavailable(c)
		}
		entry.Action = actionAllow

		// No upstream configured — return stub response for development
		if gw.upstream == nil {
			return c.Status(200).JSON(fiber.Map{
				"id":     "chatcmpl-stub",
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

		resp, err := gw.upstream.Forward(gw.base, upstreamPath, sanitized)
		if err != nil {
			return upstreamError(c, err)
		}
		if !resp.Stream() {
			defer resp.Close()
			data, err := resp.ReadAll()
			if err != nil {
				return upstreamError(c, err)
			}
			c.Set(fiber.HeaderContentType, resp.ContentType)
			return c.Status(resp.Status).Send(data)
		}

		// Headers go out when the handler returns; the writer runs on its own
		// goroutine and must not touch c.
		streaming = true
		gw.audit.wg.Add(1)
		c.Set(fiber.HeaderContentType, resp.ContentType)
		c.Set(fiber.HeaderCacheControl, "no-cache")
		c.Status(resp.Status).Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			defer gw.audit.wg.Done()
			defer resp.Close()
			relay(w, resp)
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			gw.audit.record(entry)
		})
		return nil
	}
}

// relay copies an event stream as it arrives. It returns when the upstream ends,
// fails, or the client is gone; closing resp then cancels the upstream.
func relay(w *bufio.Writer, resp *proxy.Response) {
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				slog.Info("client left during stream", "err", werr)
				return
			}
			if werr := w.Flush(); werr != nil {
				slog.Info("client left during stream", "err", werr)
				return
			}
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			// The 200 is already sent, so the failure goes in the stream.
			slog.Warn("upstream stream failed", "err", err)
			event, _ := json.Marshal(errorBody(streamFailure(err), "server_error", "upstream_error"))
			_, _ = fmt.Fprintf(w, "data: %s\n\n", event)
			_ = w.Flush()
			return
		}
	}
}

func streamFailure(err error) string {
	var upstream *proxy.Error
	if errors.As(err, &upstream) {
		return upstream.Message
	}
	return "upstream unavailable"
}

// evaluatePolicies loads policies fresh, so an update applies to the next request.
// Any error means the request must not go upstream.
func (gw gateway) evaluatePolicies(entry requestEntry, vars *policy.Vars) (policy.Decision, error) {
	ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
	defer cancel()
	policies, err := gw.policies(ctx, entry.OrgID, entry.ProjectID)
	if err != nil {
		return policy.Decision{}, fmt.Errorf("load: %w", err)
	}
	return gw.engine.EvaluateAll(ctx, policies, vars)
}

// policyVars builds the rule inputs. request.tokens is an estimate from the body
// size (the same 4 bytes per token as the chunker) because nothing tokenizes yet.
func policyVars(entry requestEntry, body map[string]any, bodyBytes int) *policy.Vars {
	vars := &policy.Vars{
		RequestModel:       entry.Model,
		RequestTenantID:    entry.OrgID.String(),
		RequestTokens:      bodyBytes / 4,
		IsMCPResponse:      hasToolMessage(body["messages"]),
		InjectionLabel:     entry.Scores.Injection.Label,
		InjectionScore:     float64(entry.Scores.Injection.Confidence),
		ToxicityScore:      float64(entry.Scores.Toxicity.Confidence),
		AnomalyHasTagChars: entry.Report.HadTagChars,
		AnomalyHasBidi:     entry.Report.HadBidi,
		AnomalyScore:       entry.Report.AnomalyScore,
		PIIEntities:        []string{},
		TopicCategories:    []string{},
	}
	for _, entity := range entry.Scores.PII {
		vars.PIIEntities = append(vars.PIIEntities, entity.Type)
	}
	for _, topic := range entry.Scores.Topic {
		if topic.Confidence > 0 {
			vars.TopicCategories = append(vars.TopicCategories, topic.Label)
		}
	}
	return vars
}

func hasToolMessage(raw any) bool {
	messages, _ := raw.([]any)
	for _, msg := range messages {
		if m, ok := msg.(map[string]any); ok && m["role"] == "tool" {
			return true
		}
	}
	return false
}

func errorBody(message, errType, code string) fiber.Map {
	return fiber.Map{"error": fiber.Map{"message": message, "type": errType, "code": code}}
}

// blockResponse is the single shape for every guardrail refusal.
func blockResponse(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusBadRequest).JSON(errorBody(message, "invalid_request_error", "content_filter"))
}

func policyUnavailable(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).
		JSON(errorBody("policy evaluation unavailable", "server_error", "policy_unavailable"))
}

// upstreamError turns a proxy failure into its client response.
func upstreamError(c *fiber.Ctx, err error) error {
	var upstream *proxy.Error
	if !errors.As(err, &upstream) {
		slog.Error("upstream request failed", "err", err)
		return c.Status(fiber.StatusBadGateway).
			JSON(errorBody("upstream unavailable", "server_error", "upstream_unavailable"))
	}
	slog.Warn("upstream request failed", "err", err)
	if upstream.RetryAfter != "" {
		c.Set(fiber.HeaderRetryAfter, upstream.RetryAfter)
	}
	errType := "server_error"
	if upstream.Status < 500 {
		errType = "invalid_request_error"
	}
	return c.Status(upstream.Status).JSON(errorBody(upstream.Message, errType, upstream.Code))
}

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	ListenAddr      string
	ModelsPath      string
	DatabaseURL     string
	UpstreamURL     string
	UpstreamKey     string
	UpstreamTimeout time.Duration
}

func loadConfig() (config, error) {
	timeout, err := time.ParseDuration(getenv("UPSTREAM_LLM_TIMEOUT", proxy.DefaultTimeout.String()))
	if err != nil {
		return config{}, fmt.Errorf("UPSTREAM_LLM_TIMEOUT: %w", err)
	}
	if timeout <= 0 {
		return config{}, errors.New("UPSTREAM_LLM_TIMEOUT must be positive")
	}
	return config{
		ListenAddr:      getenv("LISTEN_ADDR", ":8080"),
		ModelsPath:      getenv("MODELS_PATH", "./models"),
		DatabaseURL:     getenv("DATABASE_URL", ""),
		UpstreamURL:     os.Getenv("UPSTREAM_LLM_URL"),
		UpstreamKey:     os.Getenv("UPSTREAM_LLM_KEY"),
		UpstreamTimeout: timeout,
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// dbKeyLookup resolves an API key hash to its org and project.
func dbKeyLookup(db *pgxpool.Pool) tenant.LookupFn {
	return func(ctx context.Context, keyHash string) (uuid.UUID, uuid.UUID, error) {
		var orgID uuid.UUID
		var projectID *uuid.UUID
		err := db.QueryRow(ctx, `SELECT org_id, project_id FROM lookup_api_key($1)`, keyHash).
			Scan(&orgID, &projectID)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}
		if projectID == nil {
			return orgID, uuid.Nil, nil
		}
		return orgID, *projectID, nil
	}
}

// dbPolicyLoader reads enabled policies inside the org's RLS scope. Project
// policies come before org-wide ones, then oldest first; updated_at is not used
// so that editing a policy does not reorder it.
func dbPolicyLoader(db *pgxpool.Pool) policyLoader {
	return func(ctx context.Context, orgID, projectID uuid.UUID) ([]policy.Policy, error) {
		var policies []policy.Policy
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, version, rules FROM policies
				 WHERE org_id = $1 AND enabled AND (project_id IS NULL OR project_id = $2)
				 ORDER BY project_id IS NULL, created_at, id`,
				orgID, nullUUID(projectID))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				p := policy.Policy{OrgID: orgID, ProjectID: projectID}
				var rules []byte
				if err := rows.Scan(&p.ID, &p.Version, &rules); err != nil {
					return err
				}
				if err := json.Unmarshal(rules, &p.Rules); err != nil {
					return fmt.Errorf("policy %s: %w", p.ID, err)
				}
				policies = append(policies, p)
			}
			return rows.Err()
		})
		return policies, err
	}
}
