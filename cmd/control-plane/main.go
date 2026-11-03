package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/auth"
	"github.com/promptshield/promptshield/internal/policy"
	"github.com/promptshield/promptshield/internal/tenant"
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

	cfg := loadConfig()
	if cfg.JWTSecret == "" {
		slog.Error("JWT_SECRET is required")
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

	app := fiber.New(fiber.Config{
		ServerHeader: "promptshield-cp",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})
	if cfg.AllowedOrigins != "" {
		app.Use(cors.New(cors.Config{AllowOrigins: cfg.AllowedOrigins}))
	}
	app.Use(logger.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	v1 := app.Group("/v1")

	v1.Post("/auth/login", limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
	}), login(db, secret))

	authed := v1.Group("", auth.Required(secret))

	authed.Post("/organizations", createOrg(db))
	authed.Post("/cel/validate", validateCEL(eng))

	viewer := auth.RequireRole(db, auth.RoleViewer)
	admin := auth.RequireRole(db, auth.RoleAdmin)

	authed.Get("/organizations/:orgId", viewer, getOrg(db))

	authed.Get("/organizations/:orgId/api-keys", admin, listAPIKeys(db))
	authed.Post("/organizations/:orgId/api-keys", admin, createAPIKey(db))
	authed.Delete("/organizations/:orgId/api-keys/:keyId", admin, revokeAPIKey(db))

	authed.Get("/organizations/:orgId/policies", viewer, listPolicies(db))
	authed.Post("/organizations/:orgId/policies", admin, createPolicy(db, eng))
	authed.Put("/organizations/:orgId/policies/:id", admin, updatePolicy(db, eng))
	authed.Delete("/organizations/:orgId/policies/:id", admin, deletePolicy(db))

	authed.Get("/organizations/:orgId/requests", viewer, listRequests(db))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
			ID        uuid.UUID `json:"id"`
			Name      string    `json:"name"`
			Slug      string    `json:"slug"`
			Tier      string    `json:"tier"`
			CreatedAt time.Time `json:"created_at"`
		}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`SELECT id, name, slug, tier, created_at FROM organizations WHERE id = $1`, id).
				Scan(&org.ID, &org.Name, &org.Slug, &org.Tier, &org.CreatedAt)
		})
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(org)
	}
}

func listAPIKeys(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		keys := []fiber.Map{}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT key_prefix, alias, created_at, expires_at, revoked_at
				 FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var prefix string
				var alias *string
				var createdAt time.Time
				var expiresAt, revokedAt *time.Time
				if err := rows.Scan(&prefix, &alias, &createdAt, &expiresAt, &revokedAt); err != nil {
					return err
				}
				keys = append(keys, fiber.Map{
					"key_prefix": prefix,
					"alias":      alias,
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
		}
		_ = c.BodyParser(&req)

		// Generate random key: ps_<32 hex chars>
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "key gen failed"})
		}
		raw := "ps_" + hex.EncodeToString(buf)
		hash := tenant.HashKey(raw)
		prefix := raw[:11] // "ps_" + 8 chars

		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, project_id, expires_at)
				 VALUES ($1, $2, $3, $4, $5, $6)`,
				hash, prefix, req.Alias, id, req.ProjectID, req.ExpiresAt)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		// Return plaintext key once only — cannot be recovered after this
		return c.Status(201).JSON(fiber.Map{
			"key":        raw,
			"key_prefix": prefix,
			"alias":      req.Alias,
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
				`SELECT id, name, description, version, enabled, rules, created_at, updated_at
				 FROM policies WHERE org_id = $1 ORDER BY updated_at DESC`, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var p pRow
				if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Version, &p.Enabled,
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
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and rules are required"})
		}
		rules, err := validateRules(eng, req.Rules)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		id := uuid.New()
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`INSERT INTO policies (id, org_id, name, description, rules) VALUES ($1,$2,$3,$4,$5)`,
				id, org, req.Name, req.Description, rules)
			return err
		})
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
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if req.Rules != nil {
			if req.Rules, err = validateRules(eng, req.Rules); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
		}
		var updated int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			tag, err := tx.Exec(c.Context(),
				`UPDATE policies SET
				 name = COALESCE(NULLIF($1,''), name),
				 description = COALESCE(NULLIF($2,''), description),
				 rules = COALESCE($3, rules),
				 enabled = COALESCE($4, enabled),
				 version = version + 1,
				 updated_at = NOW()
				 WHERE id = $5 AND org_id = $6`,
				req.Name, req.Description, req.Rules, req.Enabled, pID, org)
			updated = tag.RowsAffected()
			return err
		})
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

// validateRules checks each rule and returns the list to store, with rule IDs filled in.
func validateRules(eng *policy.Engine, raw json.RawMessage) (json.RawMessage, error) {
	rules, err := eng.ValidateRules(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rules)
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
			CreatedAt      time.Time  `json:"created_at"`
		}
		reqs := []row{}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT id, model, action, rule_id, injection_label, injection_score, toxicity_score, anomaly_score,
				        had_tag_chars, had_bidi, latency_ms, created_at
				 FROM requests WHERE org_id = $1
				 ORDER BY created_at DESC LIMIT $2`, id, limit)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.ID, &r.Model, &r.Action, &r.RuleID, &r.InjectionLabel, &r.InjectionScore, &r.ToxicityScore,
					&r.AnomalyScore, &r.HadTagChars, &r.HadBidi, &r.LatencyMs, &r.CreatedAt); err != nil {
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
}

func loadConfig() appConfig {
	return appConfig{
		ListenAddr:     getenv("LISTEN_ADDR", ":8081"),
		DatabaseURL:    getenv("DATABASE_URL", "postgres://ps_app:ps_app@localhost:5432/promptshield?sslmode=disable"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		AdminEmail:     os.Getenv("ADMIN_EMAIL"),
		AdminPassword:  os.Getenv("ADMIN_PASSWORD"),
		AllowedOrigins: os.Getenv("ALLOWED_ORIGINS"),
	}
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
