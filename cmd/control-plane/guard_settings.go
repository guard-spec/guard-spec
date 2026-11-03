package main

import (
	"encoding/json"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/auth"
	"github.com/promptshield/promptshield/internal/indirect"
	"github.com/promptshield/promptshield/internal/tenant"
)

// getGuardSettings returns the org's scan overrides (organizations.guard_settings).
func getGuardSettings(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var raw []byte
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(), `SELECT guard_settings FROM organizations WHERE id = $1`, id).Scan(&raw)
		})
		if err != nil {
			return serverError(c, err)
		}
		s, err := indirect.ParseSettings(raw)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(s)
	}
}

// putGuardSettings replaces the org's scan overrides. The body is validated
// with the gateway's own parser, so the gateway never reads settings it
// would refuse (and fail closed on).
func putGuardSettings(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		s, err := indirect.ParseSettings(c.Body())
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		raw, err := json.Marshal(s)
		if err != nil {
			return serverError(c, err)
		}
		err = tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`UPDATE organizations SET guard_settings = $1, updated_at = NOW() WHERE id = $2`, raw, id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("org guard settings changed", "org", id, "settings", string(raw), "by", auth.UserID(c))
		return c.JSON(s)
	}
}
