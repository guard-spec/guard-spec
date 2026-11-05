package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits on an organization's L3 exemplars (org_exemplars, migration 009).
// The gateway embeds every exemplar of an org when its version changes, so
// both the count and the length are bounded.
const (
	maxExemplarsPerOrg = 1000
	maxExemplarRunes   = 4000
	maxSourceRunes     = 200
)

type exemplarRow struct {
	ID        uuid.UUID `json:"id"`
	Label     string    `json:"label"`
	Text      string    `json:"text"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type exemplarInput struct {
	Label  *string `json:"label"`
	Text   *string `json:"text"`
	Source *string `json:"source"`
}

// validate checks the fields that are set; create requires label and text.
func (in *exemplarInput) validate(create bool) error {
	if create && (in.Label == nil || in.Text == nil) {
		return errors.New("label and text are required")
	}
	if in.Label != nil && *in.Label != "block" && *in.Label != "allow" {
		return errors.New("label must be block or allow")
	}
	if in.Text != nil {
		t := strings.TrimSpace(*in.Text)
		if t == "" || !utf8.ValidString(t) || utf8.RuneCountInString(t) > maxExemplarRunes {
			return errors.New("text must be 1 to 4000 characters of UTF-8")
		}
		in.Text = &t
	}
	if in.Source != nil {
		s := strings.TrimSpace(*in.Source)
		if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxSourceRunes {
			return errors.New("source must be at most 200 characters")
		}
		if s == "" {
			s = "manual"
		}
		in.Source = &s
	}
	return nil
}

// listExemplars returns the org's exemplars and their version.
func listExemplars(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		pg, err := parsePage(c, true)
		if err != nil {
			return badPage(c, err)
		}
		ks := keyset{sort: "created_at", id: "id"}
		out := []exemplarRow{}
		var version, total int64
		err = tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if err := tx.QueryRow(c.Context(), `SELECT exemplars_version FROM organizations WHERE id = $1`, id).Scan(&version); err != nil {
				return err
			}
			args := []any{id}
			filter := ""
			if label := c.Query("label"); label != "" {
				args = append(args, label)
				filter += fmt.Sprintf(" AND label = $%d", len(args))
			}
			if q := c.Query("q"); q != "" {
				args = append(args, likePattern(q))
				filter += fmt.Sprintf(" AND text ILIKE $%d", len(args))
			}
			if pg.Enveloped {
				if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM org_exemplars WHERE org_id = $1`+filter, args...).
					Scan(&total); err != nil {
					return err
				}
			}
			cond, args, err := ks.where(pg, args)
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT id, label, text, source, created_at, updated_at FROM org_exemplars
				 WHERE org_id = $1`+filter+cond+ks.orderLimit(pg), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r exemplarRow
				if err := rows.Scan(&r.ID, &r.Label, &r.Text, &r.Source, &r.CreatedAt, &r.UpdatedAt); err != nil {
					return err
				}
				out = append(out, r)
			}
			return rows.Err()
		})
		if errors.Is(err, errBadCursor) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		if pg.Enveloped {
			items, next := page(out, pg.Limit, func(r exemplarRow) pageCursor { return timeCursor(r.CreatedAt, r.ID.String()) })
			return c.JSON(fiber.Map{"items": items, "next_cursor": next, "total": total, "version": version})
		}
		return c.JSON(fiber.Map{"data": out, "version": version})
	}
}

var errTooManyExemplars = errors.New("too many exemplars")

func createExemplar(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var in exemplarInput
		if err := c.BodyParser(&in); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if err := in.validate(true); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		source := "manual"
		if in.Source != nil {
			source = *in.Source
		}
		id := uuid.New()
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			// Lock the org row so that concurrent inserts cannot pass the cap together.
			if _, err := tx.Exec(c.Context(), `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, org); err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM org_exemplars WHERE org_id = $1`, org).Scan(&n); err != nil {
				return err
			}
			if n >= maxExemplarsPerOrg {
				return errTooManyExemplars
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO org_exemplars (id, org_id, label, text, source, created_by) VALUES ($1,$2,$3,$4,$5,$6)`,
				id, org, *in.Label, *in.Text, source, nullUUID(auth.UserID(c)))
			return err
		})
		if errors.Is(err, errTooManyExemplars) {
			return c.Status(409).JSON(fiber.Map{"error": "an organization can have at most 1000 exemplars"})
		}
		if err != nil {
			return serverError(c, err)
		}
		// The text is the tenant's data: log only its id and label.
		slog.Info("org exemplar created", "org", org, "id", id, "label", *in.Label, "by", auth.UserID(c))
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
}

func updateExemplar(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid exemplar id"})
		}
		var in exemplarInput
		if err := c.BodyParser(&in); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if err := in.validate(false); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		var updated int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			tag, err := tx.Exec(c.Context(),
				`UPDATE org_exemplars SET
				 label = COALESCE($1, label), text = COALESCE($2, text), source = COALESCE($3, source),
				 updated_at = NOW()
				 WHERE id = $4 AND org_id = $5`,
				in.Label, in.Text, in.Source, id, org)
			updated = tag.RowsAffected()
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if updated == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		slog.Info("org exemplar updated", "org", org, "id", id, "by", auth.UserID(c))
		return c.JSON(fiber.Map{"id": id, "updated": true})
	}
}

func deleteExemplar(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid exemplar id"})
		}
		var deleted int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			tag, err := tx.Exec(c.Context(), `DELETE FROM org_exemplars WHERE id = $1 AND org_id = $2`, id, org)
			deleted = tag.RowsAffected()
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if deleted == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		slog.Info("org exemplar deleted", "org", org, "id", id, "by", auth.UserID(c))
		return c.Status(204).Send(nil)
	}
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
