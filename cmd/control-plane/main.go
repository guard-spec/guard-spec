package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/policy"
	"github.com/promptshield/promptshield/internal/tenant"
)

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
	app.Use(cors.New())
	app.Use(logger.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	v1 := app.Group("/v1")

	v1.Post("/organizations", createOrg(db))
	v1.Get("/organizations/:orgId", getOrg(db))

	v1.Get("/organizations/:orgId/api-keys", listAPIKeys(db))
	v1.Post("/organizations/:orgId/api-keys", createAPIKey(db))
	v1.Delete("/organizations/:orgId/api-keys/:keyId", revokeAPIKey(db))

	v1.Get("/organizations/:orgId/policies", listPolicies(db))
	v1.Post("/organizations/:orgId/policies", createPolicy(db, eng))
	v1.Put("/organizations/:orgId/policies/:id", updatePolicy(db, eng))
	v1.Delete("/organizations/:orgId/policies/:id", deletePolicy(db))

	v1.Post("/cel/validate", validateCEL(eng))

	v1.Get("/organizations/:orgId/requests", listRequests(db))

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

func createOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name is required"})
		}
		id := uuid.New()
		if _, err := db.Exec(c.Context(),
			`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
			id, req.Name, req.Slug); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(201).JSON(fiber.Map{"id": id, "name": req.Name, "slug": req.Slug})
	}
}

func getOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		var org struct {
			ID        uuid.UUID `json:"id"`
			Name      string    `json:"name"`
			Slug      string    `json:"slug"`
			Tier      string    `json:"tier"`
			CreatedAt time.Time `json:"created_at"`
		}
		row := db.QueryRow(c.Context(),
			`SELECT id, name, slug, tier, created_at FROM organizations WHERE id = $1`, orgID)
		if err := row.Scan(&org.ID, &org.Name, &org.Slug, &org.Tier, &org.CreatedAt); err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(org)
	}
}

func listAPIKeys(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		rows, err := db.Query(c.Context(),
			`SELECT key_prefix, alias, created_at, expires_at, revoked_at
			 FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		defer rows.Close()

		var keys []fiber.Map
		for rows.Next() {
			var prefix string
			var alias *string
			var createdAt time.Time
			var expiresAt, revokedAt *time.Time
			if err := rows.Scan(&prefix, &alias, &createdAt, &expiresAt, &revokedAt); err != nil {
				continue
			}
			keys = append(keys, fiber.Map{
				"key_prefix": prefix,
				"alias":      alias,
				"created_at": createdAt,
				"expires_at": expiresAt,
				"revoked":    revokedAt != nil,
			})
		}
		if keys == nil {
			keys = []fiber.Map{}
		}
		return c.JSON(fiber.Map{"data": keys})
	}
}

func createAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
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

		if _, err := db.Exec(c.Context(),
			`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, project_id, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			hash, prefix, req.Alias, orgID, req.ProjectID, req.ExpiresAt); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		// keyId param is the key_prefix (we display prefix, never the hash)
		if _, err := db.Exec(c.Context(),
			`UPDATE api_keys SET revoked_at = NOW()
			 WHERE key_prefix = $1 AND org_id = $2 AND revoked_at IS NULL`,
			c.Params("keyId"), orgID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(204).Send(nil)
	}
}

func listPolicies(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		rows, err := db.Query(c.Context(),
			`SELECT id, name, description, version, enabled, rules, created_at, updated_at
			 FROM policies WHERE org_id = $1 ORDER BY updated_at DESC`, orgID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		defer rows.Close()

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
		var policies []pRow
		for rows.Next() {
			var p pRow
			if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Version, &p.Enabled,
				&p.Rules, &p.CreatedAt, &p.UpdatedAt); err != nil {
				continue
			}
			policies = append(policies, p)
		}
		if policies == nil {
			policies = []pRow{}
		}
		return c.JSON(fiber.Map{"data": policies})
	}
}

func createPolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		var req struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Rules       json.RawMessage `json:"rules"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and rules are required"})
		}
		if err := validateRules(eng, req.Rules); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		id := uuid.New()
		if _, err := db.Exec(c.Context(),
			`INSERT INTO policies (id, org_id, name, description, rules) VALUES ($1,$2,$3,$4,$5)`,
			id, orgID, req.Name, req.Description, req.Rules); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
}

func updatePolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := uuid.Parse(c.Params("orgId"))
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
			if err := validateRules(eng, req.Rules); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
		}
		if _, err := db.Exec(c.Context(),
			`UPDATE policies SET
			 name = COALESCE(NULLIF($1,''), name),
			 description = COALESCE(NULLIF($2,''), description),
			 rules = COALESCE($3, rules),
			 enabled = COALESCE($4, enabled),
			 version = version + 1,
			 updated_at = NOW()
			 WHERE id = $5 AND org_id = $6`,
			req.Name, req.Description, req.Rules, req.Enabled, pID, orgID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"id": pID, "updated": true})
	}
}

func deletePolicy(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := uuid.Parse(c.Params("orgId"))
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		if _, err := db.Exec(c.Context(),
			`DELETE FROM policies WHERE id = $1 AND org_id = $2`, pID, orgID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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

// validateRules compiles each rule to CEL and returns an error if any fail.
func validateRules(eng *policy.Engine, raw json.RawMessage) error {
	var rules []policy.Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	for _, rule := range rules {
		celExpr, err := policy.JSONASTToCEL(rule.Condition)
		if err != nil {
			return err
		}
		if err := eng.ValidateCEL(celExpr); err != nil {
			return err
		}
	}
	return nil
}

// ── Config ────────────────────────────────────────────────────────────────────

func listRequests(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		limit := 100
		if l := c.QueryInt("limit", 100); l > 0 && l <= 1000 {
			limit = l
		}
		rows, err := db.Query(c.Context(),
			`SELECT id, action, injection_label, injection_score, toxicity_score, anomaly_score,
			        had_tag_chars, had_bidi, latency_ms, created_at
			 FROM requests WHERE org_id = $1
			 ORDER BY created_at DESC LIMIT $2`, orgID, limit)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		defer rows.Close()

		type row struct {
			ID             uuid.UUID `json:"id"`
			Action         string    `json:"action"`
			InjectionLabel *string   `json:"injection_label"`
			InjectionScore float32   `json:"injection_score"`
			ToxicityScore  float32   `json:"toxicity_score"`
			AnomalyScore   float32   `json:"anomaly_score"`
			HadTagChars    bool      `json:"had_tag_chars"`
			HadBidi        bool      `json:"had_bidi"`
			LatencyMs      *int      `json:"latency_ms"`
			CreatedAt      time.Time `json:"created_at"`
		}
		var reqs []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ID, &r.Action, &r.InjectionLabel, &r.InjectionScore, &r.ToxicityScore,
				&r.AnomalyScore, &r.HadTagChars, &r.HadBidi, &r.LatencyMs, &r.CreatedAt); err != nil {
				continue
			}
			reqs = append(reqs, r)
		}
		if reqs == nil {
			reqs = []row{}
		}
		return c.JSON(fiber.Map{"data": reqs, "total": len(reqs)})
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

type appConfig struct {
	ListenAddr  string
	DatabaseURL string
}

func loadConfig() appConfig {
	return appConfig{
		ListenAddr:  getenv("LISTEN_ADDR", ":8081"),
		DatabaseURL: getenv("DATABASE_URL", "postgres://ps:ps@localhost:5432/promptshield?sslmode=disable"),
	}
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
