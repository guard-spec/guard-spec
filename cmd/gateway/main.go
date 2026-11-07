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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/google/uuid"
	appconfig "github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/guard-spec/guard-spec/internal/tracing"
	"github.com/guard-spec/guard-spec/internal/version"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	injectionBlockThreshold = 0.85
	anomalyBlockThreshold   = 0.6

	// policyTimeout bounds loading and evaluating one request's policies.
	policyTimeout = 5 * time.Second
	// shutdownGrace is how long open streams get before they are cancelled.
	shutdownGrace = 5 * time.Second

	// Values of requests.action. A log rule is recorded with its rule_id under
	// the action the request ended with, and anything refused as block.
	actionAllow      = "allow"
	actionRoute      = "route" // allowed by a route rule and sent to its target
	actionBlock      = "block"
	actionError      = "error"       // the upstream failed, or the client left before it answered
	actionOutputLeak = "output_leak" // the canary showed up in the output
)

var (
	errBlocked            = errors.New("potential prompt injection detected")
	errUnsupportedContent = errors.New("unsupported content format")
)

func main() {
	if len(os.Args) > 1 && version.IsFlag(os.Args[1]) {
		fmt.Println("gateway", version.String())
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ops, err := loadOpsConfig(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	var upstream *proxy.Proxy
	if cfg.UpstreamURL != "" {
		upstream, err = proxy.New(proxy.Config{
			BaseURL:   cfg.UpstreamURL,
			Key:       cfg.UpstreamKey,
			Timeout:   cfg.UpstreamTimeout,
			Propagate: ops.Propagate,
		})
		if err != nil {
			slog.Error("upstream config", "err", err)
			os.Exit(1)
		}
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

	// L1 rules plus the model layers that load (L2 classifier, L3 embeddings).
	detector, err := buildDetector(context.Background(), cfg.Detector, dbExemplarStore{db: db})
	if err != nil {
		slog.Error("load detector", "err", err)
		os.Exit(1)
	}
	// The classifier can be reloaded at run time, and a shadow candidate
	// compared with it (reload.go, shadow.go).
	live := ml.NewLive(detector)
	defer func() { _ = live.Close() }()
	runner := inference.NewRunnerWith(inference.FusedBackend{F: live})

	base, cancelUpstream := context.WithCancel(context.Background())
	defer cancelUpstream()

	stopOps, err := startOps(base, ops)
	if err != nil {
		slog.Error("observability", "err", err)
		os.Exit(1)
	}
	defer stopOps()

	var output *outputguard.Guard
	if cfg.Output != nil {
		output = outputguard.New(*cfg.Output)
	}
	slog.Info("output guard", "enabled", output != nil)

	// Alert events (docs/alerts.md): written in batches after the response.
	var emitter *events.Emitter
	if !strings.EqualFold(os.Getenv("ALERTS_EVENTS"), "off") {
		emitter = events.New(db, events.Config{Source: "gateway"})
	}
	flagAt := flagThreshold(os.Getenv)
	audit := newAuditLog(dbAuditStore(db, cfg.AuditStoreContent, emitter, flagAt).write)
	// Retried refusals add to the first one's row (audit_dedupe.go).
	audit.dedupe = newRefusalDedupe(cfg.AuditDedupeWindow)
	slog.Info("scan config", "roles", cfg.Scan.Roles.String(), "spotlight", cfg.Scan.Spotlight,
		"indirect_threshold", cfg.Scan.IndirectThreshold, "tool_prefixes", cfg.Scan.ToolPrefixes)
	app := newApp(gateway{
		detector:         newLiveStatus(detector, live, cfg.Detector.RequireML),
		live:             live,
		adminToken:       cfg.AdminToken,
		runner:           runner,
		engine:           engine,
		policies:         dbPolicyLoader(db),
		audit:            audit,
		upstream:         upstream,
		upstreamProvider: cfg.UpstreamProvider,
		policyRoutes:     dbPolicyRouteLoader(db),
		upstreams:        dbUpstreamLoader(db),
		pool: newUpstreamPool(poolConfig{propagate: ops.Propagate, allowPrivate: cfg.UpstreamAllowPrivate,
			keyOrgs: cfg.UpstreamKeyOrgs, getenv: os.Getenv}),
		output:   output,
		base:     base,
		scan:     &cfg.Scan,
		settings: dbSettingsLoader(db),
		limits:   newRateLimiter(ops.RateLimit, dbKeyLimits(db)),
		cache:    newScanCache(cfg.ScanCacheSize, scanCacheTTL),

		waitOnHalfClose: cfg.WaitOnHalfClose,
	}, dbKeyLookup(db))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	watchReload(ctx, live)

	go func() {
		slog.Info("gateway listening", "addr", cfg.ListenAddr, "version", version.String())
		if err := app.Listen(cfg.ListenAddr); err != nil {
			slog.Error("listen", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = app.ShutdownWithTimeout(shutdownGrace)
	cancelUpstream()
	audit.close() // the pool closes after this; pending rows need it
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	emitter.Close(closeCtx) // after the audit rows, which emit events
	cancelClose()
}

// policyLoader returns the enabled policies for a request, in evaluation order.
type policyLoader func(ctx context.Context, orgID, projectID uuid.UUID) ([]policy.Policy, error)

// gateway holds what the handlers depend on. A nil upstream means stub
// responses when no named upstream applies either.
type gateway struct {
	runner   *inference.Runner
	engine   *policy.Engine
	policies policyLoader
	audit    *auditLog
	upstream *proxy.Proxy // UPSTREAM_LLM_URL
	// upstreamProvider is UPSTREAM_LLM_PROVIDER: "anthropic" lets
	// /v1/messages go to UPSTREAM_LLM_URL.
	upstreamProvider string
	// policyRoutes, when set, replaces policies: it also reads the upstreams
	// the request may need, in the same transaction (routing.go).
	policyRoutes policyRouteLoader
	// upstreams finds an org's named upstreams and defaults when policyRoutes
	// is not set; nil: none, so a route rule fails closed.
	upstreams upstreamLoader
	pool      *upstreamPool
	output    *outputguard.Guard // nil: responses are passed on unchanged
	limits    *rateLimiter       // nil: no rate limit
	// cache keeps detector results of unchanged texts (scan_cache.go); nil: off.
	cache *scanCache
	// base is the parent of upstream calls and scans: a fiber ctx dies with the
	// handler, and fasthttp's RequestCtx.Done races with server shutdown.
	base context.Context

	// waitOnHalfClose keeps the upstream running when the client sends FIN, for
	// clients that half-close and still wait for the answer. See watchClose.
	waitOnHalfClose bool

	scan     *scanConfig    // nil: defaultScanConfig
	settings settingsLoader // per-org overrides; nil: none

	// detector is what /readyz reports: the active detection layers.
	detector detectorStatus
	// live is the reloadable detector behind runner, with shadow mode; nil
	// in tests that score with a plain runner.
	live *ml.Live
	// adminToken is GATEWAY_ADMIN_TOKEN; "" turns the /admin routes off.
	adminToken string
}

// newApp builds the Fiber app with all gateway routes.
func newApp(gw gateway, lookup tenant.LookupFn) *fiber.App {
	app := fiber.New(fiber.Config{
		ServerHeader: "guard-spec",
	})

	app.Use(observe()) // metrics and the request span; first, so it sees every response
	app.Use(cors.New())

	// Health check — no auth required
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "version": version.String()})
	})
	// Readiness — no auth required. Reports which detection layers run, so a
	// release image started without /models shows it runs L1 only. 503 (same
	// body, status "degraded") when a layer the configuration requires is
	// missing; a degraded gateway that does not require its models stays ready.
	app.Get("/readyz", func(c *fiber.Ctx) error {
		det := gw.detector.current()
		status, code := "ready", fiber.StatusOK
		if !det.ready() {
			status, code = "degraded", fiber.StatusServiceUnavailable
		}
		return c.Status(code).JSON(fiber.Map{"status": status, "version": version.String(), "detector": det})
	})
	// Model reload and status, with GATEWAY_ADMIN_TOKEN (reload.go).
	registerAdmin(app, gw)

	// Errors of the Anthropic routes, the key check and rate limit included,
	// in the Anthropic error shape (messages.go).
	app.Use(anthropicErrors())
	// Errors of /v1/responses and /v1/embeddings in the OpenAI shape (responses.go).
	app.Use(openAIErrors())

	// All proxy routes require a valid API key.
	app.Use(tenant.Middleware(lookup))
	if gw.limits != nil {
		app.Use(gw.limits.middleware())
	}

	// OpenAI-compatible proxy
	app.Post("/v1/chat/completions", chatHandler(gw, "/chat/completions"))
	app.Post("/v1/completions", chatHandler(gw, "/completions"))
	app.Get("/v1/models", modelsHandler(gw))
	// OpenAI Responses API, to an upstream that serves it (responses.go)
	app.Post("/v1/responses", proxyHandler(gw, responsesFormat))
	app.Post("/v1/embeddings", embeddingsHandler(gw))

	// Anthropic Messages API, to an upstream with provider anthropic
	app.Post("/v1/messages", proxyHandler(gw, messagesFormat))
	app.Post("/v1/messages/count_tokens", countTokensHandler(gw))

	// Direct guardrail endpoints
	app.Post("/guardrail/scan", scanHandler(gw))
	app.Post("/guardrail/scan/tools", scanToolsHandler(gw))
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

// requestEntry is one row of the requests table.
type requestEntry struct {
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	Model     string
	Action    string
	RuleID    uuid.UUID
	Scores    inference.Scores
	Report    sanitizer.Report
	Output    outputguard.Counts // what the output guard acted on, never the content
	// Redacted counts the untrusted texts replaced with a placeholder
	// (INDIRECT_ACTION=redact); their scores are in Indirect.
	Redacted int
	// ServerState: a /v1/responses request referred to conversation state the
	// upstream keeps, which the gateway cannot scan: refused, or passed with
	// RESPONSES_SERVER_STATE=allow.
	ServerState bool

	Indirect indirect.Verdict // strongest untrusted part (tool result, tool description)
	// SourceRole is where the strongest injection finding came from: user,
	// system, assistant, tool or tool_description.
	SourceRole string
	// RouteTarget is the named upstream the request went to, or was meant to
	// go to when it failed closed; "" for UPSTREAM_LLM_URL and the stub.
	RouteTarget string
	LatencyMs   int
	Request     string // body as received; hashed, stored only if enabled
	Response    string // buffered upstream body; empty when streamed

	// Shadow collects the shadow model's comparison (shadow.go); nil when
	// shadow mode is off or the request was not sampled. ShadowWait is how
	// long the audit writer waits for it.
	Shadow     *ml.Recorder
	ShadowWait time.Duration

	// ID is the requests row id, also the request_id of alert events.
	ID uuid.UUID
	// For alert events only, not stored (events.go): the API key prefix, the
	// layer that blocked the request ("" when nothing detected it), and an
	// upstream failure.
	KeyPrefix      string
	Detected       string
	UpstreamID     uuid.UUID
	UpstreamStatus int
	ErrorKind      string

	// For metrics only, not stored.
	Route  string
	Status int // HTTP status sent to the client
	Start  time.Time

	// Retried refusals (audit_dedupe.go). KeyHash is the caller's API key
	// hash and Trigger a hash of the text that triggered a refusal; neither
	// is stored. RepeatCount is the repeat_count column: how many identical
	// refusals the row stands for (0 or 1: NULL).
	KeyHash     string
	Trigger     string
	RepeatCount int64
	repeat      *refusalRecord
	repeatFirst bool
}

// newEntry starts a row for the caller. Handlers must copy what they need from
// c before going async, because fiber reuses it once the handler returns.
func newEntry(c *fiber.Ctx) requestEntry {
	orgID, _ := tenant.OrgID(c)
	c.Locals(auditedKey, true) // observeEntry records this request's metrics
	return requestEntry{ID: uuid.New(), KeyPrefix: apiKeyPrefix(c), KeyHash: tenant.KeyHash(c), OrgID: orgID,
		ProjectID: tenant.ProjectID(c), Action: actionBlock, Request: string(c.Body()), Route: routeLabel(c.Path()),
		Status: fiber.StatusOK, Start: time.Now()}
}

// auditLog writes rows without delaying the response, and tracks them so that
// shutdown can wait for those still in flight. The closed flag and the mutex
// keep every wg.Add ahead of the final Wait: once close has begun, a row is
// written synchronously by its caller instead of being added to the group.
type auditLog struct {
	write func(requestEntry)
	// dedupe folds retried refusals into one row (audit_dedupe.go); nil: off.
	dedupe *refusalDedupe
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newAuditLog(write func(requestEntry)) *auditLog {
	return &auditLog{write: write}
}

// hold counts a request in flight, so that close waits for its row as well as
// for rows already queued. The returned release must be called after the row is
// recorded. Once close has begun it counts nothing and release does nothing.
func (a *auditLog) hold() (release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return func() {}
	}
	a.wg.Add(1)
	var once sync.Once
	return func() { once.Do(a.wg.Done) }
}

func (a *auditLog) record(e requestEntry) {
	observeEntry(e) // metrics count every request, repeats included
	e.repeat, e.repeatFirst = a.dedupe.track(&e)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.write(e) // too late to queue: write it before returning
		return
	}
	a.wg.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.wg.Done()
		a.write(e)
	}()
}

// close stops queueing and waits for every queued row and held request.
func (a *auditLog) close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	a.wg.Wait()
}

// wait waits for the rows queued so far, without closing. Tests use it.
func (a *auditLog) wait() { a.wg.Wait() }

// outputTags renders output guard counts for the pii_entities column, as
// "output:<kind>=<count>", sorted. auditTags adds the input redactions.
func outputTags(counts outputguard.Counts) []string {
	var tags []string
	for kind, n := range counts {
		if n > 0 {
			tags = append(tags, fmt.Sprintf("output:%s=%d", kind, n))
		}
	}
	sort.Strings(tags)
	return tags
}

// auditTags is the pii_entities column: the output guard's counts, then
// "input:redacted=<n>" when untrusted content was redacted, and
// "input:server_state=1" when a /v1/responses request referred to
// conversation state the upstream keeps.
func auditTags(e requestEntry) []string {
	tags := outputTags(e.Output)
	if e.Redacted > 0 {
		tags = append(tags, fmt.Sprintf("input:redacted=%d", e.Redacted))
	}
	if e.ServerState {
		tags = append(tags, "input:server_state=1")
	}
	return tags
}

// logRequest writes one requests row, logging a failure.
func logRequest(db *pgxpool.Pool, storeContent bool, e requestEntry) {
	if err := insertRequest(db, storeContent, e); err != nil {
		slog.Warn("request log write failed", "err", err, "action", e.Action)
	}
}

// insertRequest writes one requests row.
func insertRequest(db *pgxpool.Pool, storeContent bool, e requestEntry) error {
	if e.OrgID == uuid.Nil {
		slog.Warn("request log skipped: no org")
		return nil
	}
	var repeats *int64
	if e.RepeatCount > 1 {
		repeats = &e.RepeatCount
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
	var target *string
	if e.RouteTarget != "" {
		target = &e.RouteTarget
	}
	req, resp := digest(e.Request), digest(e.Response)
	// Wait for the shadow comparison before the transaction, not inside it.
	shadow, withShadow := shadowRow(e)
	return tenant.WithOrg(ctx, db, e.OrgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, auditInsert,
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
			auditTags(e),
			storeContent,
			req.SHA256, req.Bytes, req.Content,
			resp.SHA256, resp.Bytes, resp.Content,
			target,
			nullUUID(e.ID),
			repeats,
		)
		if err != nil || !withShadow {
			return err
		}
		return insertShadow(ctx, tx, e, shadow)
	})
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

	roles  *indirect.Roles // what is classified; nil: indirect.DefaultRoles
	source indirect.Source // source of the text being cleaned; "" is user
	parts  []scanPart      // sanitized text to classify, by source (scan_roles.go)
	tools  []indirect.Tool // tool definitions to classify
	// toolPrefixes, when set, limits the tools classified (SCAN_TOOL_PREFIXES).
	toolPrefixes []string
	// org keys the scan cache.
	org uuid.UUID
	// latest is SCAN_HISTORY=latest on /v1/messages: history holds while an
	// earlier turn is cleaned, whose own text is then not classified.
	latest, history bool
	// useCache scores parts through gateway.cache (/v1/messages).
	useCache bool
	// redactFn replaces the block being cleaned with a placeholder; nil when
	// it is not untrusted content.
	redactFn func()
	// blocked is a hash of the text the sanitizer refused (errBlocked), the
	// trigger of a retried refusal (audit_dedupe.go).
	blocked string
	// schemaKey names the tools' schema field: parameters (OpenAI, the
	// default) or input_schema (the Messages API).
	schemaKey string
	// allowServerState is RESPONSES_SERVER_STATE=allow; serverState is set
	// when a /v1/responses request refers to state the upstream keeps.
	allowServerState, serverState bool
}

func (g *textGuard) toolSchemaKey() string {
	if g.schemaKey == "" {
		return "parameters"
	}
	return g.schemaKey
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
		g.blocked = triggerHash(text)
		return "", errBlocked
	}
	g.texts = append(g.texts, cleaned)
	g.collect(cleaned)
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
	if err := g.guardTools(body); err != nil {
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
			raw, present := p["text"]
			if !present {
				continue
			}
			// Anything but a string would reach the upstream unscanned.
			text, ok := raw.(string)
			if !ok {
				return errUnsupportedContent
			}
			cleaned, err := g.clean(text)
			if err != nil {
				return err
			}
			p["text"] = cleaned
		}
		return nil
	default:
		return errUnsupportedContent
	}
}

// guardMessages covers roles carrying untrusted text. System and assistant turns
// come from the integrating application and are left unchanged; see
// guardMessage for what is classified.
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
		if err := g.guardMessage(m); err != nil {
			return err
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
	var refused *paramError
	switch {
	case errors.Is(err, errBlocked):
		return blockResponse(c, "Request blocked: potential prompt injection detected.")
	case errors.Is(err, errUnsupportedContent):
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	case errors.As(err, &refused):
		return c.Status(fiber.StatusBadRequest).JSON(errorBody(refused.message, "invalid_request_error", refused.code))
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
func chatHandler(gw gateway, upstreamPath string) fiber.Handler {
	return proxyHandler(gw, openAIFormat(upstreamPath))
}

// proxyHandler sanitizes the untrusted text of a request in format f, applies
// the fixed thresholds and the org's policies, then proxies the sanitized body
// to f.path. Every request gets one audit row: refused unless it reaches the
// point where entry.Action is set.
func proxyHandler(gw gateway, f apiFormat) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		release := gw.audit.hold()
		entry := newEntry(c)
		gw := gw.forRequest(&entry)
		tctx := requestContext(c, gw.base) // gw.base with the request span, for child spans
		streaming := false                 // the stream writes the row when it ends
		defer func() {
			if !streaming {
				entry.Status = c.Response().StatusCode()
				entry.LatencyMs = int(time.Since(start).Milliseconds())
				gw.audit.record(entry)
				release()
			}
		}()

		// Parse request body
		body, err := decodeBody(c.Body())
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		entry.Model, _ = body["model"].(string)
		// The headers the format takes from the client, copied: fiber reuses
		// its buffers once the handler returns.
		var call proxy.Call
		if f.call != nil {
			if call, err = f.call(c); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "invalid_header"))
			}
		}

		scanCfg, err := gw.scanConfigFor(entry.OrgID)
		if err != nil {
			slog.Error("org scan settings unavailable", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}

		// Extract + sanitize untrusted text
		guard := textGuard{roles: &scanCfg.Roles, toolPrefixes: scanCfg.toolPrefixes(), org: entry.OrgID,
			latest: f.history && scanCfg.History == historyLatest, useCache: f.history,
			allowServerState: scanCfg.ServerState == serverStateAllow}
		_, endSpan := tracing.Start(tctx, "sanitize")
		err = f.guardBody(&guard, body)
		endSpan(err)
		entry.Report, entry.ServerState = guard.report, guard.serverState
		if err != nil {
			if errors.Is(err, errBlocked) {
				entry.Detected = layerSanitizer
				entry.Trigger = guard.blocked
			}
			return guardError(c, err)
		}

		// Classify: user, system and tool-call text together, each tool result
		// and tool definition on its own (scan_roles.go).
		_, endSpan = tracing.Start(tctx, "detect")
		verdict, err := gw.scoreRequest(&guard)
		endSpan(err)
		if err != nil {
			if errors.Is(err, errUnsupportedContent) {
				return guardError(c, err)
			}
			return scanError(c, err)
		}
		entry.Scores, entry.Indirect, entry.SourceRole = verdict.Scores, verdict.Indirect, verdict.SourceRole
		if verdict.Direct >= scanCfg.injectionThreshold() {
			slog.Info("blocked injection", "score", verdict.Direct, "source_role", verdict.SourceRole)
			entry.Detected = modelLayer(verdict.Scores)
			entry.Trigger = verdict.DirectTrigger
			return blockResponse(c, "Request blocked: prompt injection detected.")
		}
		blocking := verdict.Indirect.Score
		if scanCfg.IndirectAction == indirect.ActionRedact {
			// Tool results and documents over the threshold are replaced with a
			// placeholder; what is left, and tool definitions, still block.
			redacted, rest := guard.redactUntrusted(scanCfg.IndirectThreshold)
			if redacted > 0 {
				entry.Redacted = redacted
				blocking = max(rest, verdict.Tools)
				slog.Info("redacted indirect injection", "parts", redacted, "score", verdict.Indirect.Score,
					"source", verdict.Indirect.Source, "category", verdict.Indirect.Category)
			}
		}
		if blocking >= scanCfg.IndirectThreshold {
			slog.Info("blocked indirect injection", "score", verdict.Indirect.Score,
				"source", verdict.Indirect.Source, "category", verdict.Indirect.Category)
			entry.Detected = layerIndirect
			entry.Trigger = verdict.IndirectTrigger
			return blockResponse(c, "Request blocked: prompt injection detected in tool or document content.")
		}

		// Mark tool results for the model (SPOTLIGHT). Off by default.
		if _, err := f.spotlight(body, scanCfg.Spotlight); err != nil {
			slog.Error("spotlight", "err", err)
			return c.Status(fiber.StatusServiceUnavailable).
				JSON(errorBody("guardrail unavailable", "server_error", "guardrail_unavailable"))
		}

		sanitized, err := json.Marshal(body)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}

		// Policies run after the fixed thresholds, so they can only tighten them.
		_, endSpan = tracing.Start(tctx, "policy")
		decision, routes, err := gw.evaluatePolicies(entry, policyVars(entry, body, len(sanitized)))
		endSpan(err)
		if err != nil {
			slog.Error("policy evaluation failed", "org", entry.OrgID, "err", err)
			return policyUnavailable(c)
		}
		entry.RuleID = decision.RuleID
		if len(decision.Logged) > 0 {
			slog.Info("policy log rules matched", "rules", decision.Logged)
			if entry.RuleID == uuid.Nil {
				entry.RuleID = decision.Logged[0] // the row has room for one rule
			}
		}
		switch decision.Action {
		case policy.ActionAllow, policy.ActionRoute:
		case policy.ActionBlock:
			slog.Info("blocked by policy", "rule", decision.RuleID)
			entry.Detected = layerPolicy
			entry.Trigger = verdict.DirectTrigger + verdict.IndirectTrigger
			return blockResponse(c, "Request blocked by policy.")
		default:
			// redact is refused when saved, so this is a stale rule.
			slog.Error("rule has an action the gateway cannot enforce",
				"rule", decision.RuleID, "action", decision.Action)
			return policyUnavailable(c)
		}

		// Pick the upstream: route rule, project default, org default, env, stub.
		target, err := gw.resolveRoute(entry, decision, routes)
		entry.RouteTarget = target.name
		if errors.Is(err, errRouteUnavailable) {
			entry.Action = actionError
			entry.ErrorKind = errorKindConnect
			return c.Status(fiber.StatusBadGateway).
				JSON(errorBody("route target unavailable", "server_error", "route_unavailable"))
		}
		if err != nil {
			slog.Error("upstreams unavailable", "org", entry.OrgID, "err", err)
			metrics.PolicyErrors.WithLabelValues("route").Inc()
			return policyUnavailable(c)
		}
		if f.checkRoute != nil {
			if err := f.checkRoute(target); err != nil {
				slog.Info("upstream does not serve the request format", "org", entry.OrgID, "upstream", target.name,
					"provider", target.provider)
				entry.Action, entry.UpstreamID = actionError, target.id
				return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "unsupported_upstream"))
			}
		}
		entry.Action = actionAllow
		if decision.Action == policy.ActionRoute {
			entry.Action = actionRoute
		}
		model, err := target.applyModel(entry.Model)
		if errors.Is(err, errModelNotAllowed) {
			// The audit row keeps the refused model and the upstream.
			slog.Info("model not allowed by upstream", "org", entry.OrgID, "upstream", target.name, "model", entry.Model)
			entry.ErrorKind, entry.UpstreamID = errorKindModel, target.id
			entry.Action = actionBlock
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(
				"model "+strconv.Quote(entry.Model)+" is not allowed for this upstream", "invalid_request_error", "model_not_allowed"))
		}
		capped, err := target.capTokens(body)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "invalid_max_tokens"))
		}
		if model != entry.Model || capped {
			// The audit row records the model actually sent upstream; policies
			// saw the requested one.
			if model != entry.Model {
				body["model"] = model
				entry.Model = model
			}
			if sanitized, err = json.Marshal(body); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}

		// No upstream configured — return stub response for development
		if target.proxy == nil {
			return c.Status(200).JSON(f.stub(body["model"]))
		}

		// The output guard needs the canary in the prompt before it goes upstream.
		var scan *outputguard.Scanner
		if gw.output != nil {
			canary := ""
			if gw.output.Config().Canary != outputguard.CanaryOff {
				if canary, err = outputguard.NewCanary(); err != nil {
					slog.Error("canary", "err", err)
					return c.Status(fiber.StatusServiceUnavailable).
						JSON(errorBody("guardrail unavailable", "server_error", "guardrail_unavailable"))
				}
				if f.injectCanary(body, canary) {
					if sanitized, err = json.Marshal(body); err != nil {
						return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
					}
				} else {
					canary = "" // no system prompt to carry it (legacy completions)
				}
			}
			scan = gw.output.ForRequest(canary)
		}

		// Cancelled when the client hangs up, so a client that leaves while the
		// upstream is still thinking does not hold the upstream until its timeout.
		ctx, cancel := context.WithCancel(tctx)
		conn := c.Context().Conn()
		stopWatch := watchClose(conn, cancel, !gw.waitOnHalfClose)
		handedOff := false // the stream writer owns cancel once it is set up
		defer func() {
			if !handedOff {
				stopWatch()
				cancel()
			}
		}()

		entry.UpstreamID = target.id
		resp, err := target.proxy.Do(ctx, f.path, sanitized, call)
		if err != nil {
			entry.Action = actionError
			entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
			clientLeft(ctx, gw.base)
			return upstreamError(c, err)
		}
		if !resp.Stream() {
			defer resp.Close()
			data, err := resp.ReadAll()
			if err != nil {
				entry.Action = actionError
				entry.ErrorKind, entry.UpstreamStatus = upstreamErrorKind(err)
				clientLeft(ctx, gw.base)
				return upstreamError(c, err)
			}
			entry.Response = string(data)
			if scan != nil {
				counts := outputguard.Counts{}
				_, endSpan := tracing.Start(tctx, "output_guard")
				data, err = f.guardResponse(scan, data, counts)
				endSpan(err)
				entry.Output = counts
				if errors.Is(err, outputguard.ErrToolCanary) {
					entry.Action = actionOutputLeak
					slog.Warn("canary leaked in tool-call arguments", "org", entry.OrgID)
					return blockResponse(c, outputLeakMessage)
				}
				if err != nil {
					entry.Action = actionError
					slog.Warn("upstream response could not be checked", "err", err)
					return c.Status(fiber.StatusBadGateway).
						JSON(errorBody("upstream response could not be checked", "server_error", "upstream_error"))
				}
				if counts[outputguard.KindCanary] > 0 {
					entry.Action = actionOutputLeak
					slog.Warn("canary leaked in output", "org", entry.OrgID)
					if gw.output.Config().Canary == outputguard.CanaryBlock {
						return blockResponse(c, outputLeakMessage)
					}
				}
			}
			entry.Response = string(data)
			c.Set(fiber.HeaderContentType, resp.ContentType)
			return c.Status(resp.Status).Send(data)
		}

		// Headers go out when the handler returns; the writer runs on its own
		// goroutine and must not touch c. fasthttp does not read the connection
		// between the two, so the writer watches it again for the client leaving.
		streaming, handedOff = true, true
		stopWatch()
		var events streamGuard // a nil interface, not a nil pointer in one, when off
		errorEvent := f.streamError
		if scan != nil {
			events = f.newStream(scan)
			if e, ok := events.(interface {
				ErrorEvent(message, errType, code string) []byte
			}); ok {
				errorEvent = e.ErrorEvent // numbered after the events sent
			}
		}
		c.Set(fiber.HeaderContentType, resp.ContentType)
		c.Set(fiber.HeaderCacheControl, "no-cache")
		c.Status(resp.Status).Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			defer release()
			defer cancel()
			defer resp.Close()
			stop := watchClose(conn, cancel, !gw.waitOnHalfClose)
			_, endSpan := tracing.Start(tctx, "output_guard.stream") // the relay, guarded when events is set
			outcome := relay(w, resp, events, errorEvent)
			endSpan(nil)
			stop()
			entry.Status = resp.Status
			switch outcome {
			case relayUpstreamFailed:
				entry.Action = actionError
				entry.ErrorKind = errorKindConnect
			case relayBlocked:
				entry.Action = actionOutputLeak
			}
			if events != nil {
				entry.Output = events.Acted()
				if entry.Output[outputguard.KindCanary] > 0 {
					entry.Action = actionOutputLeak
				}
			}
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			gw.audit.record(entry)
		})
		return nil
	}
}

const outputLeakMessage = "Response blocked: the model output leaked protected content."

// clientLeft logs when an upstream call failed because the client hung up.
func clientLeft(ctx, base context.Context) {
	if ctx.Err() != nil && base.Err() == nil {
		slog.Info("client left before the upstream answered; upstream cancelled")
	}
}

// injectCanary puts the canary into the system prompt: appended to a leading
// system message, or as a new one. It reports false when the body has no chat
// messages to carry it.
func injectCanary(body map[string]any, canary string) bool {
	messages, ok := body["messages"].([]any)
	if !ok {
		return false
	}
	note := outputguard.CanaryNote(canary)
	if len(messages) > 0 {
		if m, ok := messages[0].(map[string]any); ok && m["role"] == "system" {
			if text, ok := m["content"].(string); ok {
				m["content"] = text + "\n\n" + note
				return true
			}
		}
	}
	body["messages"] = append([]any{map[string]any{"role": "system", "content": note}}, messages...)
	return true
}

type relayOutcome int

const (
	relayDone relayOutcome = iota
	relayClientGone
	relayUpstreamFailed
	relayBlocked
)

// streamGuard is the output guard of one event stream, in the format of its
// API: *outputguard.EventStream or *outputguard.MessageStream.
type streamGuard interface {
	Write(p []byte) []byte
	Close() []byte
	Blocked() bool
	Failed() bool
	Acted() outputguard.Counts
}

// relay copies an event stream as it arrives, through the output guard when
// events is set. It returns when the upstream ends, fails, the client is gone,
// or the guard blocks the stream; closing resp then cancels the upstream.
// errorEvent renders the event that tells the client why a stream stopped.
func relay(w *bufio.Writer, resp *proxy.Response, events streamGuard, errorEvent func(message, errType, code string) []byte) relayOutcome {
	send := func(p []byte) bool {
		if len(p) == 0 {
			return true
		}
		if _, err := w.Write(p); err != nil {
			slog.Info("client left during stream", "err", err)
			return false
		}
		if err := w.Flush(); err != nil {
			slog.Info("client left during stream", "err", err)
			return false
		}
		return true
	}
	// guardStopped ends the stream with an error event when the output guard
	// blocked it (a leaked canary) or met a chunk it cannot check.
	guardStopped := func() (relayOutcome, bool) {
		var event []byte
		var outcome relayOutcome
		switch {
		case events == nil:
			return 0, false
		case events.Blocked():
			slog.Warn("canary leaked in output; stream stopped")
			event = errorEvent(outputLeakMessage, "invalid_request_error", "content_filter")
			outcome = relayBlocked
		case events.Failed():
			slog.Warn("upstream stream chunk could not be checked; stream stopped")
			event = errorEvent("upstream response could not be checked", "server_error", "upstream_error")
			outcome = relayUpstreamFailed
		default:
			return 0, false
		}
		_, _ = w.Write(event)
		_ = w.Flush()
		return outcome, true
	}
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Read(buf)
		if n > 0 {
			out := buf[:n]
			if events != nil {
				out = events.Write(out)
			}
			if !send(out) {
				return relayClientGone
			}
			if outcome, stopped := guardStopped(); stopped {
				return outcome
			}
		}
		if errors.Is(err, io.EOF) {
			if events != nil && !send(events.Close()) {
				return relayClientGone
			}
			if outcome, stopped := guardStopped(); stopped {
				return outcome
			}
			return relayDone
		}
		if err != nil {
			// The 200 is already sent, so the failure goes in the stream.
			slog.Warn("upstream stream failed", "err", err)
			if events != nil {
				// Text the guard still holds has been checked; a half-written
				// event has not, and is dropped.
				if !send(events.Close()) {
					return relayClientGone
				}
				if outcome, stopped := guardStopped(); stopped {
					return outcome
				}
			}
			// The blank line ends any event the upstream left half-written, so the
			// error is parsed as an event of its own rather than glued onto it.
			_, _ = w.Write(errorEvent(streamFailure(err), "server_error", "upstream_error"))
			_ = w.Flush()
			return relayUpstreamFailed
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
// With gw.policyRoutes it also returns the upstreams the request may need,
// read in the same transaction.
func (gw gateway) evaluatePolicies(entry requestEntry, vars *policy.Vars) (policy.Decision, *routeSnapshot, error) {
	ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
	defer cancel()
	var (
		policies []policy.Policy
		snap     *routeSnapshot
		err      error
	)
	if gw.policyRoutes != nil {
		policies, snap, err = gw.policyRoutes(ctx, entry.OrgID, entry.ProjectID)
	} else {
		policies, err = gw.policies(ctx, entry.OrgID, entry.ProjectID)
	}
	if err != nil {
		metrics.PolicyErrors.WithLabelValues("load").Inc()
		return policy.Decision{}, nil, fmt.Errorf("load: %w", err)
	}
	decision, err := gw.engine.EvaluateAll(ctx, policies, vars)
	if err != nil {
		metrics.PolicyErrors.WithLabelValues("eval").Inc()
	}
	return decision, snap, err
}

// policyVars builds the rule inputs. request.tokens is an estimate from the body
// size (the same 4 bytes per token as the chunker) because nothing tokenizes yet.
func policyVars(entry requestEntry, body map[string]any, bodyBytes int) *policy.Vars {
	vars := &policy.Vars{
		RequestModel:       entry.Model,
		RequestTenantID:    entry.OrgID.String(),
		RequestTokens:      bodyBytes / 4,
		IsMCPResponse:      hasToolMessage(body["messages"]) || hasToolOutputItem(body["input"]),
		InjectionLabel:     entry.Scores.Injection.Label,
		InjectionScore:     float64(entry.Scores.Injection.Confidence),
		AnomalyHasTagChars: entry.Report.HadTagChars,
		AnomalyHasBidi:     entry.Report.HadBidi,
		AnomalyScore:       entry.Report.AnomalyScore,
		IndirectScore:      entry.Indirect.Score,
		IndirectSource:     string(entry.Indirect.Source),
		SourceRole:         entry.SourceRole,
	}
	vars.ScoreL1, vars.ScoreL2, vars.ScoreL3 = vars.InjectionScore, -1, -1
	if d := entry.Scores.Injection.Detail; d != nil {
		vars.ScoreL1, vars.ScoreL2, vars.ScoreL3, vars.InjectionCat = d.L1, d.L2, d.L3, d.Category
	}
	return vars
}

// hasToolMessage reports a tool result: a message with role tool, or a
// tool_result block (the Messages API).
func hasToolMessage(raw any) bool {
	messages, _ := raw.([]any)
	for _, msg := range messages {
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		if m["role"] == "tool" {
			return true
		}
		blocks, _ := m["content"].([]any)
		for _, b := range blocks {
			if block, ok := b.(map[string]any); ok && block["type"] == "tool_result" {
				return true
			}
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
	// Only a 4xx is the client's to see as-is. A server-side failure is reported
	// by the gateway: its own timeout stays 504, anything else is a 502.
	status, code, errType := upstream.Status, upstream.Code, "invalid_request_error"
	if status >= 500 {
		errType = "server_error"
		if code != "upstream_timeout" && status != fiber.StatusBadGateway {
			status, code = fiber.StatusBadGateway, "upstream_error"
		}
	}
	return c.Status(status).JSON(errorBody(upstream.Message, errType, code))
}

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	ListenAddr string
	// Detector is DETECTOR_*, MODEL_DIR (or MODELS_PATH), L2_MODEL / L2_MODEL_DIR and L3_MODEL / L3_MODEL_DIR.
	Detector        ml.Config
	DatabaseURL     string
	UpstreamURL     string
	UpstreamKey     string
	UpstreamTimeout time.Duration
	// UpstreamProvider is UPSTREAM_LLM_PROVIDER: openai_compatible (the
	// default) or anthropic, which also serves /v1/messages.
	UpstreamProvider string
	// UpstreamKeyOrgs is UPSTREAM_KEY_ORGS: which orgs may use which
	// UPSTREAM_KEY_* variable for their named upstreams. Empty: none.
	UpstreamKeyOrgs appconfig.KeyOrgs
	// UpstreamAllowPrivate is UPSTREAM_ALLOW_PRIVATE: org-defined upstreams may
	// resolve to loopback, private, unique local and CGNAT addresses.
	UpstreamAllowPrivate bool
	// AuditStoreContent stores request and response content in audit rows for
	// every org. Off by default; an org can opt in on its own (decision D6).
	AuditStoreContent bool
	// Output is the output guard's configuration; nil turns the guard off.
	// There are no per-org settings yet, so it applies to every org.
	Output *outputguard.Config
	// WaitOnHalfClose is CLIENT_HALF_CLOSE=wait.
	WaitOnHalfClose bool
	// Scan is SCAN_ROLES, SPOTLIGHT and INDIRECT_BLOCK_THRESHOLD; an org can
	// override roles and spotlight in organizations.guard_settings.
	Scan scanConfig
	// ScanCacheSize is SCAN_CACHE_SIZE: entries of the scan cache; 0 is off.
	ScanCacheSize int
	// AdminToken is GATEWAY_ADMIN_TOKEN: the bearer token of /admin/models
	// (reload.go). Empty: those routes are off.
	AdminToken string
	// AuditDedupeWindow is AUDIT_DEDUPE_WINDOW: retried refusals within it
	// add to the first one's audit row (audit_dedupe.go); 0 is off.
	AuditDedupeWindow time.Duration
}

func loadConfig() (config, error) {
	timeout, err := time.ParseDuration(getenv("UPSTREAM_LLM_TIMEOUT", proxy.DefaultTimeout.String()))
	if err != nil {
		return config{}, fmt.Errorf("UPSTREAM_LLM_TIMEOUT: %w", err)
	}
	if timeout <= 0 {
		return config{}, errors.New("UPSTREAM_LLM_TIMEOUT must be positive")
	}
	output, err := loadOutputConfig(os.Getenv)
	if err != nil {
		return config{}, err
	}
	var waitOnHalfClose bool
	switch strings.ToLower(getenv("CLIENT_HALF_CLOSE", "cancel")) {
	case "cancel":
	case "wait":
		waitOnHalfClose = true
	default:
		return config{}, errors.New("CLIENT_HALF_CLOSE must be cancel or wait")
	}
	scan, err := loadScanConfig(os.Getenv)
	if err != nil {
		return config{}, err
	}
	detector, err := ml.ConfigFromEnv(os.Getenv)
	if err != nil {
		return config{}, err
	}
	storeContent, err := strconv.ParseBool(getenv("AUDIT_STORE_CONTENT", "false"))
	if err != nil {
		return config{}, fmt.Errorf("AUDIT_STORE_CONTENT must be true or false: %w", err)
	}
	keyOrgs, err := appconfig.ParseKeyOrgs(os.Getenv("UPSTREAM_KEY_ORGS"))
	if err != nil {
		return config{}, err
	}
	allowPrivate, err := strconv.ParseBool(getenv("UPSTREAM_ALLOW_PRIVATE", "false"))
	if err != nil {
		return config{}, fmt.Errorf("UPSTREAM_ALLOW_PRIVATE must be true or false: %w", err)
	}
	cacheSize, err := strconv.Atoi(getenv("SCAN_CACHE_SIZE", strconv.Itoa(defaultScanCacheSize)))
	if err != nil || cacheSize < 0 || cacheSize > 1_000_000 {
		return config{}, errors.New("SCAN_CACHE_SIZE must be a number from 0 to 1000000")
	}
	dedupeWindow, err := parseDedupeWindow(strings.TrimSpace(os.Getenv("AUDIT_DEDUPE_WINDOW")))
	if err != nil {
		return config{}, err
	}
	provider := strings.ToLower(strings.TrimSpace(getenv("UPSTREAM_LLM_PROVIDER", providerOpenAICompatible)))
	if provider != providerOpenAICompatible && provider != providerAnthropic {
		return config{}, errors.New("UPSTREAM_LLM_PROVIDER must be openai_compatible or anthropic")
	}
	cfg := config{
		UpstreamProvider:     provider,
		ScanCacheSize:        cacheSize,
		ListenAddr:           getenv("LISTEN_ADDR", ":8080"),
		Detector:             detector,
		DatabaseURL:          getenv("DATABASE_URL", ""),
		UpstreamURL:          os.Getenv("UPSTREAM_LLM_URL"),
		UpstreamKey:          os.Getenv("UPSTREAM_LLM_KEY"),
		UpstreamTimeout:      timeout,
		UpstreamKeyOrgs:      keyOrgs,
		UpstreamAllowPrivate: allowPrivate,
		Output:               output,
		WaitOnHalfClose:      waitOnHalfClose,
		AuditStoreContent:    storeContent,
		Scan:                 scan,
		AdminToken:           strings.TrimSpace(os.Getenv("GATEWAY_ADMIN_TOKEN")),
		AuditDedupeWindow:    dedupeWindow,
	}
	// Refuse a default or weak database password unless GUARD_ENV=dev.
	var secrets appconfig.Checker
	secrets.DatabaseURL("DATABASE_URL", cfg.DatabaseURL)
	if cfg.AdminToken != "" {
		secrets.Secret("GATEWAY_ADMIN_TOKEN", cfg.AdminToken)
	}
	if err := secrets.Err(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

// defaultOutputConfig is the output guard when no OUTPUT_* variable is set:
// on, every image and link stripped, personal data other than IPv4 redacted,
// no canary, reasoning guarded like the answer.
func defaultOutputConfig() outputguard.Config {
	return outputguard.Config{RedactPII: true, Canary: outputguard.CanaryOff}
}

// loadOutputConfig reads the OUTPUT_* variables. It returns nil when
// OUTPUT_GUARD=off.
func loadOutputConfig(env func(string) string) (*outputguard.Config, error) {
	get := func(key, fallback string) string {
		if v := strings.TrimSpace(env(key)); v != "" {
			return strings.ToLower(v)
		}
		return fallback
	}
	switch get("OUTPUT_GUARD", "on") {
	case "on":
	case "off":
		return nil, nil
	default:
		return nil, errors.New("OUTPUT_GUARD must be on or off")
	}
	cfg := defaultOutputConfig()
	for _, host := range strings.Split(env("OUTPUT_LINK_ALLOWLIST"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			cfg.LinkAllowlist = append(cfg.LinkAllowlist, host)
		}
	}
	var err error
	if cfg.RedactPII, err = strconv.ParseBool(get("OUTPUT_PII_REDACT", "true")); err != nil {
		return nil, fmt.Errorf("OUTPUT_PII_REDACT: %w", err)
	}
	if cfg.RedactIPv4, err = strconv.ParseBool(get("OUTPUT_PII_IPV4", "false")); err != nil {
		return nil, fmt.Errorf("OUTPUT_PII_IPV4: %w", err)
	}
	switch mode := outputguard.CanaryMode(get("OUTPUT_CANARY", "off")); mode {
	case outputguard.CanaryOff, outputguard.CanaryBlock, outputguard.CanaryRedact:
		cfg.Canary = mode
	default:
		return nil, errors.New("OUTPUT_CANARY must be off, block or redact")
	}
	switch get("OUTPUT_REASONING", "guard") {
	case "guard":
	case "drop":
		cfg.DropReasoning = true
	default:
		return nil, errors.New("OUTPUT_REASONING must be guard or drop")
	}
	// Content blocks of a /v1/messages response of a type the guard does not
	// know (a server tool other than web search and web fetch, say), and output
	// items and stream events of a /v1/responses response likewise.
	switch get("OUTPUT_UNKNOWN_BLOCKS", "refuse") {
	case "refuse":
	case "pass":
		cfg.PassUnknownBlocks = true
	default:
		return nil, errors.New("OUTPUT_UNKNOWN_BLOCKS must be refuse or pass")
	}
	return &cfg, nil
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
			var err error
			policies, err = queryPolicies(ctx, tx, orgID, projectID)
			return err
		})
		return policies, err
	}
}
