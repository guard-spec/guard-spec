package main

import (
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// listMyOrgs returns the organizations the caller belongs to, with the role.
//
// org_memberships and organizations are row-level secured by app.org_id, and
// this list spans orgs, so it reads them through user_organizations
// (migration 012), a SECURITY DEFINER function that returns only the rows of
// the user it is given. The user id comes from the verified token, never from
// the request.
func listMyOrgs(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		type orgRow struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
			Slug string    `json:"slug"`
			Role string    `json:"role"`
		}
		rows, err := db.Query(c.Context(),
			`SELECT id, name, slug, role FROM user_organizations($1) ORDER BY name, id`, auth.UserID(c))
		if err != nil {
			return serverError(c, err)
		}
		defer rows.Close()
		orgs := []orgRow{}
		for rows.Next() {
			var o orgRow
			if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Role); err != nil {
				return serverError(c, err)
			}
			orgs = append(orgs, o)
		}
		if err := rows.Err(); err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": orgs})
	}
}
