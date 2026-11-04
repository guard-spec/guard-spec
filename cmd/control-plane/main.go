package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/giaplee/guard-spec/internal/retention"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/giaplee/guard-spec/web"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultOrgID is the organization seeded by migration 002.
var defaultOrgID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Handle "health" subcommand used by the Dockerfile HEALTHCHECK
	if len(os.Args) > 1 && os.Args[1] == "health" {
		resp, err := http.Get("http://localhost:8081/health")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	checkOnly := flag.Bool("check-policies", false,
		"validate every stored policy, list the failures and exit (1 if any fail); "+
			"DATABASE_URL must name a role that bypasses row-level security")
	flag.Parse()

	cfg := loadConfig()
	if *checkOnly {
		os.Exit(runPolicyCheck(context.Background(), cfg.DatabaseURL, os.Stdout))
	}
	if err := cfg.check(); err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ops, err := loadOpsConfig(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	secret := []byte(cfg.JWTSecret)

	db, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		slog.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(context.Background()); err != nil {
		slog.Error("db ping", "err", err)
		os.Exit(1)
	}

	if err := bootstrapAdmin(context.Background(), db, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		slog.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}

	eng, err := policy.New()
	if err != nil {
		slog.Error("policy engine", "err", err)
		os.Exit(1)
	}

	app := newApp(db, secret, eng, cfg.AllowedOrigins, withEnvUpstream(cfg.UpstreamURL))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := metrics.Serve(ctx, ops.MetricsAddr); err != nil {
		slog.Error("metrics listener", "addr", ops.MetricsAddr, "err", err)
		os.Exit(1)
	}
	go retention.Run(ctx, db, ops.Retention)

	go func() {
		slog.Info("control-plane listening", "addr", cfg.ListenAddr)
		if err := app.Listen(cfg.ListenAddr); err != nil {
			slog.Error("listen", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = app.Shutdown()
}

// appSettings are optional settings of newApp.
type appSettings struct {
	// envUpstreamURL is UPSTREAM_LLM_URL, for the simulator's env step.
	envUpstreamURL string
	ui             fs.FS // the admin UI; nil: web.Dist()
}

type appOption func(*appSettings)

// withEnvUpstream tells the simulator the gateway's UPSTREAM_LLM_URL.
func withEnvUpstream(url string) appOption {
	return func(s *appSettings) { s.envUpstreamURL = url }
}

// newApp builds the Fiber app with all control plane routes.
func newApp(db *pgxpool.Pool, secret []byte, eng *policy.Engine, allowedOrigins string, opts ...appOption) *fiber.App {
	settings := &appSettings{}
	for _, o := range opts {
		o(settings)
	}
	if settings.ui == nil {
		settings.ui = web.Dist()
	}
	app := fiber.New(fiber.Config{
		ServerHeader: "guard-spec-cp",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})
	app.Use(observe())
	if allowedOrigins != "" {
		app.Use(cors.New(cors.Config{AllowOrigins: allowedOrigins}))
	}
	app.Use(logger.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	mountUI(app, settings.ui)

	v1 := app.Group("/v1")

	v1.Post("/auth/login", limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
	}), login(db, secret))
	// The token is the credential here, so it gets the login's limit.
	v1.Post("/invites/accept", limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
	}), acceptInvite(db, secret))

	authed := v1.Group("", auth.Required(secret))

	authed.Post("/organizations", createOrg(db))
	authed.Post("/cel/validate", validateCEL(eng))
	// Rule editing helpers; they read no org data.
	authed.Get("/policy/schema", policySchema())
	authed.Post("/policy/parse", parseCondition(eng))
	authed.Post("/policy/format", formatCondition())

	viewer := auth.RequireRole(db, auth.RoleViewer)
	admin := auth.RequireRole(db, auth.RoleAdmin)

	authed.Get("/organizations/:orgId", viewer, getOrg(db))
	authed.Patch("/organizations/:orgId", admin, updateOrgSettings(db))
	authed.Get("/organizations/:orgId/guard-settings", viewer, getGuardSettings(db))
	authed.Put("/organizations/:orgId/guard-settings", admin, putGuardSettings(db))

	authed.Get("/organizations/:orgId/api-keys", admin, listAPIKeys(db))
	authed.Post("/organizations/:orgId/api-keys", admin, createAPIKey(db))
	authed.Patch("/organizations/:orgId/api-keys/:keyId", admin, updateAPIKey(db))
	authed.Delete("/organizations/:orgId/api-keys/:keyId", admin, revokeAPIKey(db))

	authed.Get("/organizations/:orgId/projects", viewer, listProjects(db))
	authed.Post("/organizations/:orgId/projects", admin, createProject(db))

	// Named upstreams and routing defaults (migration 011).
	authed.Get("/organizations/:orgId/upstreams", viewer, listUpstreams(db))
	authed.Post("/organizations/:orgId/upstreams", admin, createUpstream(db))
	authed.Put("/organizations/:orgId/upstreams/:id", admin, updateUpstream(db))
	authed.Delete("/organizations/:orgId/upstreams/:id", admin, deleteUpstream(db))
	authed.Put("/organizations/:orgId/default-upstream", admin, putOrgDefaultUpstream(db))
	authed.Put("/organizations/:orgId/projects/:projectId/default-upstream", admin, putProjectDefaultUpstream(db))

	// Config as code: the org's upstreams, defaults and policies as one YAML file.
	authed.Get("/organizations/:orgId/config", viewer, getConfig(db))
	authed.Put("/organizations/:orgId/config", admin, putConfig(db, eng))

	authed.Get("/organizations/:orgId/policies", viewer, listPolicies(db))
	// Before /policies/:id, which would take "simulate" as an id.
	authed.Post("/organizations/:orgId/policies/simulate", viewer, simulatePolicies(db, eng, settings))
	authed.Post("/organizations/:orgId/policies", admin, createPolicy(db, eng))
	authed.Put("/organizations/:orgId/policies/:id", admin, updatePolicy(db, eng))
	authed.Delete("/organizations/:orgId/policies/:id", admin, deletePolicy(db))

	authed.Get("/organizations/:orgId/requests", viewer, listRequests(db))

	// L3 exemplars of the org (migration 009); never stored in the repository.
	authed.Get("/organizations/:orgId/exemplars", viewer, listExemplars(db))
	authed.Post("/organizations/:orgId/exemplars", admin, createExemplar(db))
	authed.Put("/organizations/:orgId/exemplars/:id", admin, updateExemplar(db))
	authed.Delete("/organizations/:orgId/exemplars/:id", admin, deleteExemplar(db))

	// Invites, also under the short /orgs prefix.
	for _, prefix := range []string{"/organizations/:orgId", "/orgs/:orgId"} {
		authed.Get(prefix+"/invites", admin, listInvites(db))
		authed.Post(prefix+"/invites", admin, createInvite(db))
		authed.Delete(prefix+"/invites/:inviteId", admin, revokeInvite(db))
	}
	return app
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// serverError logs err and hides its details from the client.
func serverError(c *fiber.Ctx, err error) error {
	slog.Error("request failed", "path", c.Path(), "err", err)
	return c.Status(500).JSON(fiber.Map{"error": "internal error"})
}

// orgID returns the organization checked by auth.RequireRole.
func orgID(c *fiber.Ctx) uuid.UUID {
	id, _ := tenant.OrgID(c)
	return id
}

// bootstrapAdmin creates the first owner of the default organization.
func bootstrapAdmin(ctx context.Context, db *pgxpool.Pool, email, password string) error {
	if email == "" || password == "" {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return tenant.WithOrg(ctx, db, defaultOrgID, func(tx pgx.Tx) error {
		var userID uuid.UUID
		err := tx.QueryRow(ctx,
			`INSERT INTO users (email, hashed_password) VALUES ($1, $2)
			 ON CONFLICT (email) DO NOTHING RETURNING id`, email, hash).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // already bootstrapped
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')`,
			userID, defaultOrgID)
		return err
	})
}

func login(db *pgxpool.Pool, secret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		var userID uuid.UUID
		var hash *string
		err := db.QueryRow(c.Context(),
			`SELECT id, hashed_password FROM users WHERE email = $1`, req.Email).Scan(&userID, &hash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return serverError(c, err)
		}
		stored := ""
		if hash != nil {
			stored = *hash
		}
		if !auth.CheckPassword(stored, req.Password) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}
		token, err := auth.IssueToken(secret, userID)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"token": token})
	}
}

func createOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" || req.Slug == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and slug are required"})
		}
		id := uuid.New()
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if _, err := tx.Exec(c.Context(),
				`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
				id, req.Name, req.Slug); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')`,
				auth.UserID(c), id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(201).JSON(fiber.Map{"id": id, "name": req.Name, "slug": req.Slug})
	}
}

func getOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var org struct {
			ID                uuid.UUID  `json:"id"`
			Name              string     `json:"name"`
			Slug              string     `json:"slug"`
			Tier              string     `json:"tier"`
			AuditStoreContent bool       `json:"audit_store_content"`
			DefaultUpstreamID *uuid.UUID `json:"default_upstream_id"`
			CreatedAt         time.Time  `json:"created_at"`
		}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`SELECT id, name, slug, tier, audit_store_content, default_upstream_id, created_at
				 FROM organizations WHERE id = $1`, id).
				Scan(&org.ID, &org.Name, &org.Slug, &org.Tier, &org.AuditStoreContent, &org.DefaultUpstreamID, &org.CreatedAt)
		})
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(org)
	}
}

// updateOrgSettings changes org-level settings. audit_store_content opts the org
// into storing prompt and response content in audit rows (off by default, D6).
func updateOrgSettings(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var req struct {
			AuditStoreContent *bool `json:"audit_store_content"`
		}
		if err := c.BodyParser(&req); err != nil || req.AuditStoreContent == nil {
			return c.Status(400).JSON(fiber.Map{"error": "audit_store_content (boolean) is required"})
		}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`UPDATE organizations SET audit_store_content = $1, updated_at = NOW() WHERE id = $2`,
				*req.AuditStoreContent, id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("org audit content storage changed", "org", id, "enabled", *req.AuditStoreContent,
			"by", auth.UserID(c))
		return c.JSON(fiber.Map{"id": id, "audit_store_content": *req.AuditStoreContent})
	}
}

func listAPIKeys(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		keys := []fiber.Map{}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT key_prefix, alias, project_id, rpm_limit::bigint, tpm_limit, created_at, expires_at, revoked_at
				 FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var prefix string
				var alias *string
				var projectID *uuid.UUID
				var rpm, tpm *int64
				var createdAt time.Time
				var expiresAt, revokedAt *time.Time
				if err := rows.Scan(&prefix, &alias, &projectID, &rpm, &tpm, &createdAt, &expiresAt, &revokedAt); err != nil {
					return err
				}
				keys = append(keys, fiber.Map{
					"key_prefix": prefix,
					"alias":      alias,
					"project_id": projectID,
					"rpm_limit":  rpm, // null: the gateway's RATE_LIMIT_RPM; 0: unlimited
					"tpm_limit":  tpm,
					"created_at": createdAt,
					"expires_at": expiresAt,
					"revoked":    revokedAt != nil,
				})
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": keys})
	}
}

func createAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var req struct {
			Alias     string     `json:"alias"`
			ProjectID *uuid.UUID `json:"project_id"`
			ExpiresAt *time.Time `json:"expires_at"`
			RPMLimit  optLimit   `json:"rpm_limit"`
			TPMLimit  optLimit   `json:"tpm_limit"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body: " + err.Error()})
			}
		}

		// Generate random key: gs_<32 hex chars>. Keys made before the rename
		// start with ps_; they keep working, since only the hash is looked up.
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "key gen failed"})
		}
		raw := "gs_" + hex.EncodeToString(buf)
		hash := tenant.HashKey(raw)
		prefix := raw[:11] // "gs_" + 8 chars

		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, id, req.ProjectID); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, project_id, expires_at, rpm_limit, tpm_limit)
				 VALUES ($1, $2, $3, $4, $5, $6, $7::int, $8)`,
				hash, prefix, req.Alias, id, req.ProjectID, req.ExpiresAt, req.RPMLimit.Value, req.TPMLimit.Value)
			return err
		})
		if errors.Is(err, errUnknownProject) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		// Return plaintext key once only — cannot be recovered after this
		return c.Status(201).JSON(fiber.Map{
			"key":        raw,
			"key_prefix": prefix,
			"alias":      req.Alias,
			"project_id": req.ProjectID,
			"rpm_limit":  req.RPMLimit.Value,
			"tpm_limit":  req.TPMLimit.Value,
		})
	}
}

func revokeAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		// keyId param is the key_prefix (we display prefix, never the hash)
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`UPDATE api_keys SET revoked_at = NOW()
				 WHERE key_prefix = $1 AND org_id = $2 AND revoked_at IS NULL`,
				c.Params("keyId"), id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(204).Send(nil)
	}
}

func listPolicies(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		type pRow struct {
			ID          uuid.UUID       `json:"id"`
			ProjectID   *uuid.UUID      `json:"project_id"` // null: org-wide
			Name        string          `json:"name"`
			Description *string         `json:"description"`
			Version     int             `json:"version"`
			Enabled     bool            `json:"enabled"`
			Rules       json.RawMessage `json:"rules"`
			CreatedAt   time.Time       `json:"created_at"`
			UpdatedAt   time.Time       `json:"updated_at"`
		}
		policies := []pRow{}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT id, project_id, name, description, version, enabled, rules, created_at, updated_at
				 FROM policies WHERE org_id = $1 ORDER BY updated_at DESC`, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var p pRow
				if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Version, &p.Enabled,
					&p.Rules, &p.CreatedAt, &p.UpdatedAt); err != nil {
					return err
				}
				policies = append(policies, p)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": policies})
	}
}

func createPolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Rules       json.RawMessage `json:"rules"`
			ProjectID   *uuid.UUID      `json:"project_id"` // null or absent: org-wide
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and rules are required"})
		}
		rules, targets, err := validateRules(eng, req.Rules)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		id := uuid.New()
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, req.ProjectID); err != nil {
				return err
			}
			if err := checkRouteTargets(c.Context(), tx, org, targets); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO policies (id, org_id, project_id, name, description, rules) VALUES ($1,$2,$3,$4,$5,$6)`,
				id, org, req.ProjectID, req.Name, req.Description, rules)
			return err
		})
		var unknownTarget *unknownTargetError
		if errors.Is(err, errUnknownProject) || errors.As(err, &unknownTarget) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
}

func updatePolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		var req struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Enabled     *bool           `json:"enabled"`
			Rules       json.RawMessage `json:"rules"`
			ProjectID   optUUID         `json:"project_id"` // absent: unchanged; null: org-wide
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		var targets []string
		if req.Rules != nil {
			if req.Rules, targets, err = validateRules(eng, req.Rules); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
		}
		var updated int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, req.ProjectID.Value); err != nil {
				return err
			}
			if err := checkRouteTargets(c.Context(), tx, org, targets); err != nil {
				return err
			}
			tag, err := tx.Exec(c.Context(),
				`UPDATE policies SET
				 name = COALESCE(NULLIF($1,''), name),
				 description = COALESCE(NULLIF($2,''), description),
				 rules = COALESCE($3, rules),
				 enabled = COALESCE($4, enabled),
				 project_id = CASE WHEN $7 THEN $8::uuid ELSE project_id END,
				 version = version + 1,
				 updated_at = NOW()
				 WHERE id = $5 AND org_id = $6`,
				req.Name, req.Description, req.Rules, req.Enabled, pID, org,
				req.ProjectID.Set, req.ProjectID.Value)
			updated = tag.RowsAffected()
			return err
		})
		var unknownTarget *unknownTargetError
		if errors.Is(err, errUnknownProject) || errors.As(err, &unknownTarget) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		if updated == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(fiber.Map{"id": pID, "updated": true})
	}
}

func deletePolicy(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`DELETE FROM policies WHERE id = $1 AND org_id = $2`, pID, org)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(204).Send(nil)
	}
}

func validateCEL(eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Condition json.RawMessage `json:"condition"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		celExpr, err := policy.JSONASTToCEL(req.Condition)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"valid": false, "error": err.Error()})
		}
		if err := eng.ValidateCEL(celExpr); err != nil {
			return c.Status(400).JSON(fiber.Map{"valid": false, "error": err.Error()})
		}
		return c.JSON(fiber.Map{"valid": true, "cel_expression": celExpr})
	}
}

// validateRules checks each rule and returns the list to store, with rule IDs
// filled in, and the route targets the rules name (checked against the org's
// upstreams by checkRouteTargets, inside the transaction that saves them).
func validateRules(eng *policy.Engine, raw json.RawMessage) (json.RawMessage, []string, error) {
	rules, err := eng.ValidateRules(raw)
	if err != nil {
		return nil, nil, err
	}
	stored, err := json.Marshal(rules)
	return stored, routeTargets(rules), err
}

func listRequests(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		limit := 100
		if l := c.QueryInt("limit", 100); l > 0 && l <= 1000 {
			limit = l
		}

		type row struct {
			ID             uuid.UUID  `json:"id"`
			Model          *string    `json:"model"`
			Action         string     `json:"action"`
			RuleID         *uuid.UUID `json:"rule_id"`
			InjectionLabel *string    `json:"injection_label"`
			InjectionScore float32    `json:"injection_score"`
			ToxicityScore  float32    `json:"toxicity_score"`
			AnomalyScore   float32    `json:"anomaly_score"`
			HadTagChars    bool       `json:"had_tag_chars"`
			HadBidi        bool       `json:"had_bidi"`
			LatencyMs      *int       `json:"latency_ms"`
			RequestSHA256  *string    `json:"request_sha256"`
			RequestBytes   *int       `json:"request_bytes"`
			ResponseSHA256 *string    `json:"response_sha256"`
			ResponseBytes  *int       `json:"response_bytes"`
			// The named upstream the request went to (or failed to reach);
			// null for UPSTREAM_LLM_URL, the stub and refused requests.
			RouteTarget *string `json:"route_target"`
			// Present only when the org or gateway enabled content storage.
			RequestContent  *string   `json:"request_content,omitempty"`
			ResponseContent *string   `json:"response_content,omitempty"`
			CreatedAt       time.Time `json:"created_at"`
		}
		reqs := []row{}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT id, model, action, rule_id, injection_label, injection_score, toxicity_score, anomaly_score,
				        had_tag_chars, had_bidi, latency_ms,
				        request_sha256, request_bytes, response_sha256, response_bytes, route_target,
				        request_content, response_content, created_at
				 FROM requests WHERE org_id = $1
				 ORDER BY created_at DESC LIMIT $2`, id, limit)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.ID, &r.Model, &r.Action, &r.RuleID, &r.InjectionLabel, &r.InjectionScore, &r.ToxicityScore,
					&r.AnomalyScore, &r.HadTagChars, &r.HadBidi, &r.LatencyMs,
					&r.RequestSHA256, &r.RequestBytes, &r.ResponseSHA256, &r.ResponseBytes, &r.RouteTarget,
					&r.RequestContent, &r.ResponseContent, &r.CreatedAt); err != nil {
					return err
				}
				reqs = append(reqs, r)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": reqs, "total": len(reqs)})
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

type appConfig struct {
	ListenAddr     string
	DatabaseURL    string
	JWTSecret      string
	AdminEmail     string
	AdminPassword  string
	AllowedOrigins string
	// UpstreamURL is the gateway's UPSTREAM_LLM_URL, shown by the simulator
	// (without credentials). Optional.
	UpstreamURL string
}

func loadConfig() appConfig {
	return appConfig{
		ListenAddr:     getenv("LISTEN_ADDR", ":8081"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		AdminEmail:     os.Getenv("ADMIN_EMAIL"),
		AdminPassword:  os.Getenv("ADMIN_PASSWORD"),
		AllowedOrigins: os.Getenv("ALLOWED_ORIGINS"),
		UpstreamURL:    redactURL(os.Getenv("UPSTREAM_LLM_URL")),
	}
}

// redactURL drops credentials and the query from a URL that is shown to users.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// check refuses missing, default and weak secrets unless GUARD_ENV=dev.
func (cfg appConfig) check() error {
	if cfg.DatabaseURL == "" {
		return errors.New("DATABASE_URL is not set; set DATABASE_URL to the application role's connection string, " +
			"such as postgres://guardspec_app@host:5432/guardspec (password in the URL or PGPASSWORD)")
	}
	if cfg.JWTSecret == "" {
		// Even dev mode needs a key to sign with.
		return errors.New("JWT_SECRET is not set; set JWT_SECRET to a random value of at least 32 bytes " +
			"(for example: openssl rand -hex 32)")
	}
	var c config.Checker
	c.Secret("JWT_SECRET", cfg.JWTSecret)
	if cfg.AdminEmail != "" {
		c.Password("ADMIN_PASSWORD", cfg.AdminPassword)
	}
	c.DatabaseURL("DATABASE_URL", cfg.DatabaseURL)
	return c.Err()
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
