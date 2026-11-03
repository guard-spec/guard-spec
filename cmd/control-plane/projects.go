package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/tenant"
)

// Projects group API keys inside an org. A key may belong to one project, and
// a policy may be scoped to one project: the gateway then evaluates the
// project's policies first, then the org-wide ones (dbPolicyLoader).

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var errUnknownProject = errors.New("project_id does not name a project of this organization")

// checkProject verifies that id is a project of org. The foreign key alone
// does not: it is checked without RLS, so it accepts another org's project.
func checkProject(ctx context.Context, tx pgx.Tx, org uuid.UUID, id *uuid.UUID) error {
	if id == nil {
		return nil
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND org_id = $2)`,
		*id, org).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errUnknownProject
	}
	return nil
}

func createProject(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" || !slugRe.MatchString(req.Slug) {
			return c.Status(400).JSON(fiber.Map{"error": "name and slug (lowercase letters, digits, dashes) are required"})
		}
		id := uuid.New()
		var created time.Time
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, $3, $4) RETURNING created_at`,
				id, org, req.Name, req.Slug).Scan(&created)
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "slug already used in this organization"})
		}
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(201).JSON(fiber.Map{"id": id, "name": req.Name, "slug": req.Slug, "created_at": created})
	}
}

func listProjects(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		type row struct {
			ID        uuid.UUID `json:"id"`
			Name      string    `json:"name"`
			Slug      string    `json:"slug"`
			CreatedAt time.Time `json:"created_at"`
		}
		projects := []row{}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT id, name, slug, created_at FROM projects WHERE org_id = $1 ORDER BY created_at`, org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.ID, &r.Name, &r.Slug, &r.CreatedAt); err != nil {
					return err
				}
				projects = append(projects, r)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": projects})
	}
}

// optLimit is a nullable rate limit in a request body: absent leaves the
// stored value alone, null resets it to the gateway default, and a number
// sets it (0 = unlimited).
type optLimit struct {
	Set   bool
	Value *int64
}

func (o *optLimit) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return errors.New("rate limits must be whole numbers or null")
	}
	if v < 0 || v > math.MaxInt32 {
		return errors.New("rate limits must be between 0 (unlimited) and 2147483647")
	}
	o.Value = &v
	return nil
}

// optUUID is a nullable id in a request body: absent leaves the stored value
// alone, null clears it.
type optUUID struct {
	Set   bool
	Value *uuid.UUID
}

func (o *optUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return errors.New("invalid id")
	}
	o.Value = &id
	return nil
}

// updateAPIKey changes a key's rate limits. keyId is the key prefix, as in revoke.
func updateAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			RPMLimit optLimit `json:"rpm_limit"`
			TPMLimit optLimit `json:"tpm_limit"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if !req.RPMLimit.Set && !req.TPMLimit.Set {
			return c.Status(400).JSON(fiber.Map{"error": "rpm_limit or tpm_limit is required"})
		}
		var rpm *int64
		var tpm *int64
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`UPDATE api_keys SET
				   rpm_limit = CASE WHEN $1 THEN $2::int ELSE rpm_limit END,
				   tpm_limit = CASE WHEN $3 THEN $4::bigint ELSE tpm_limit END
				 WHERE key_prefix = $5 AND org_id = $6 AND revoked_at IS NULL
				 RETURNING rpm_limit::bigint, tpm_limit`,
				req.RPMLimit.Set, req.RPMLimit.Value, req.TPMLimit.Set, req.TPMLimit.Value,
				c.Params("keyId"), org).Scan(&rpm, &tpm)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"key_prefix": c.Params("keyId"), "rpm_limit": rpm, "tpm_limit": tpm})
	}
}
