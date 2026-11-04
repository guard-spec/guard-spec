package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The activity log (activity_log, migration 013) records admin actions:
// member, invite, API key, policy, upstream and security changes, 2FA resets,
// SSO provider changes and logins. An org's rows are row-level secured like
// its other tables; instance rows (org_id NULL) are read by instance
// administrators at /admin/activity. details never holds a secret: callers
// pass ids, names and flags only.

type activityEntry struct {
	Org     *uuid.UUID // nil: an instance-level row
	ActorID uuid.UUID  // uuid.Nil: no authenticated actor (a failed login)
	Action  string
	Target  string
	IP      string
	Details map[string]any
}

// writeActivity inserts one row. Failures are logged, not returned: the
// action it records has already happened.
func writeActivity(ctx context.Context, db *pgxpool.Pool, e activityEntry) {
	details, err := json.Marshal(e.Details)
	if err != nil || e.Details == nil {
		details = []byte("{}")
	}
	var actor *uuid.UUID
	if e.ActorID != uuid.Nil {
		actor = &e.ActorID
	}
	insert := func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO activity_log (org_id, actor_id, actor_email, action, target, ip, details)
			 VALUES ($1, $2, (SELECT email FROM users WHERE id = $2), $3, NULLIF($4, ''), NULLIF($5, ''), $6)`,
			e.Org, actor, e.Action, truncateRunes(e.Target, 512), truncateRunes(e.IP, 64), details)
		return err
	}
	if e.Org != nil {
		err = tenant.WithOrg(ctx, db, *e.Org, insert)
	} else {
		err = withInstanceScope(ctx, db, insert)
	}
	if err != nil {
		slog.Warn("activity log write failed", "action", e.Action, "err", err)
	}
}

// withInstanceScope runs fn in a transaction that can see instance-level
// activity rows. Only call it for instance administrators or for writes.
func withInstanceScope(ctx context.Context, db *pgxpool.Pool, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.instance_scope', 'on', true)`); err != nil {
			return err
		}
		return fn(tx)
	})
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// logActivity records an action of the authenticated caller.
func logActivity(c *fiber.Ctx, db *pgxpool.Pool, org *uuid.UUID, action, target string, details map[string]any) {
	writeActivity(c.Context(), db, activityEntry{Org: org, ActorID: auth.UserID(c), Action: action, Target: target,
		IP: c.IP(), Details: details})
}

// logUserEvent records an event of user (a login, say) at the instance level
// and in each of the user's organizations.
func logUserEvent(ctx context.Context, db *pgxpool.Pool, user uuid.UUID, action, ip string, details map[string]any) {
	writeActivity(ctx, db, activityEntry{ActorID: user, Action: action, Target: user.String(), IP: ip, Details: details})
	if user == uuid.Nil {
		return
	}
	rows, err := db.Query(ctx, `SELECT id FROM user_organizations($1)`, user)
	if err != nil {
		slog.Warn("activity log: user organizations", "err", err)
		return
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		slog.Warn("activity log: user organizations", "err", err)
		return
	}
	for _, org := range orgs {
		writeActivity(ctx, db, activityEntry{Org: &org, ActorID: user, Action: action, Target: user.String(),
			IP: ip, Details: details})
	}
}

type activityRow struct {
	ID    uuid.UUID `json:"id"`
	At    time.Time `json:"at"`
	Actor *struct {
		ID    *uuid.UUID `json:"id"`
		Email *string    `json:"email"`
	} `json:"actor"`
	Action  string          `json:"action"`
	Target  *string         `json:"target"`
	IP      *string         `json:"ip"`
	Details json.RawMessage `json:"details"`
}

// queryActivity lists rows of one org (org set) or the instance (org nil),
// newest first, filtered by actor (an id or an email) and action.
func queryActivity(c *fiber.Ctx, tx pgx.Tx, org *uuid.UUID) ([]activityRow, *string, error) {
	pg, err := parsePage(c, false)
	if err != nil {
		return nil, nil, err
	}
	ks := keyset{sort: "at", id: "id", desc: true}
	args := []any{}
	filter := "org_id IS NULL"
	if org != nil {
		args = append(args, *org)
		filter = "org_id = $1"
	}
	if actor := c.Query("actor"); actor != "" {
		if id, err := uuid.Parse(actor); err == nil {
			args = append(args, id)
			filter += fmt.Sprintf(" AND actor_id = $%d", len(args))
		} else {
			args = append(args, actor)
			filter += fmt.Sprintf(" AND lower(actor_email) = lower($%d)", len(args))
		}
	}
	if action := c.Query("action"); action != "" {
		args = append(args, action)
		filter += fmt.Sprintf(" AND action = $%d", len(args))
	}
	cond, args, err := ks.where(pg, args)
	if err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(c.Context(),
		`SELECT id, at, actor_id, actor_email, action, target, ip, details FROM activity_log WHERE `+filter+cond+
			ks.orderLimit(pg), args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := []activityRow{}
	for rows.Next() {
		var r activityRow
		var actorID *uuid.UUID
		var actorEmail *string
		if err := rows.Scan(&r.ID, &r.At, &actorID, &actorEmail, &r.Action, &r.Target, &r.IP, &r.Details); err != nil {
			return nil, nil, err
		}
		if actorID != nil || actorEmail != nil {
			r.Actor = &struct {
				ID    *uuid.UUID `json:"id"`
				Email *string    `json:"email"`
			}{actorID, actorEmail}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	items, next := page(out, pg.Limit, func(r activityRow) pageCursor { return timeCursor(r.At, r.ID.String()) })
	return items, next, nil
}

func listOrgActivity(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var items []activityRow
		var next *string
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			items, next, err = queryActivity(c, tx, &org)
			return err
		})
		return activityAnswer(c, items, next, err)
	}
}

func listInstanceActivity(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var items []activityRow
		var next *string
		err := withInstanceScope(c.Context(), db, func(tx pgx.Tx) error {
			var err error
			items, next, err = queryActivity(c, tx, nil)
			return err
		})
		return activityAnswer(c, items, next, err)
	}
}

func activityAnswer(c *fiber.Ctx, items []activityRow, next *string, err error) error {
	switch {
	case isPageError(err):
		return badPage(c, err)
	case err != nil:
		return serverError(c, err)
	}
	return pageJSON(c, items, next, -1)
}
