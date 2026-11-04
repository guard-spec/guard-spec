package main

import (
	"errors"
	"fmt"

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
//
// Paged by (name, id); q filters by name or slug.
func listMyOrgs(db *pgxpool.Pool) fiber.Handler {
	ks := keyset{sort: "name", id: "id", textSort: true}
	return func(c *fiber.Ctx) error {
		pg, err := parsePage(c, true)
		if err != nil {
			return badPage(c, err)
		}
		type orgRow struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
			Slug string    `json:"slug"`
			Role string    `json:"role"`
		}
		args := []any{auth.UserID(c)}
		filter := ""
		if q := c.Query("q"); q != "" {
			args = append(args, likePattern(q))
			filter = fmt.Sprintf(" AND (name ILIKE $%[1]d OR slug ILIKE $%[1]d)", len(args))
		}
		var total int64
		if pg.Enveloped {
			if err := db.QueryRow(c.Context(), `SELECT count(*) FROM user_organizations($1) WHERE true`+filter, args...).
				Scan(&total); err != nil {
				return serverError(c, err)
			}
		}
		cond, args, err := ks.where(pg, args)
		if err != nil {
			return badPage(c, err)
		}
		rows, err := db.Query(c.Context(),
			`SELECT id, name, slug, role FROM user_organizations($1) WHERE true`+filter+cond+ks.orderLimit(pg), args...)
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
			if errors.Is(err, errBadCursor) {
				return badPage(c, err)
			}
			return serverError(c, err)
		}
		if pg.Enveloped {
			items, next := page(orgs, pg.Limit, func(o orgRow) pageCursor { return stringCursor(o.Name, o.ID.String()) })
			return pageJSON(c, items, next, total)
		}
		return c.JSON(fiber.Map{"data": orgs})
	}
}
