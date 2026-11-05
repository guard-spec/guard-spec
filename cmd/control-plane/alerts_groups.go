// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// ── Groups ──────────────────────────────────────────────────────────────────

type groupMember struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
}

type groupRow struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	MemberIDs   []uuid.UUID   `json:"member_ids"`
	UserIDs     []uuid.UUID   `json:"user_ids"` // the same ids, the name the UI reads
	MemberCount int           `json:"member_count"`
	Members     []groupMember `json:"members,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

const groupSelect = `SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
	ARRAY(SELECT m.user_id FROM user_group_members m WHERE m.group_id = g.id ORDER BY m.added_at, m.user_id)
	FROM user_groups g`

func scanGroup(r pgx.Row) (groupRow, error) {
	var g groupRow
	err := r.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberIDs)
	if g.MemberIDs == nil {
		g.MemberIDs = []uuid.UUID{}
	}
	g.MemberCount, g.UserIDs = len(g.MemberIDs), g.MemberIDs
	return g, err
}

func (rt *alertsRuntime) listGroups(c *fiber.Ctx) error {
	org := orgID(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "g.name", id: "g.id", textSort: true}
	var list []groupRow
	var total int64
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM user_groups WHERE org_id = $1`, org).Scan(&total); err != nil {
			return err
		}
		cond, args, err := ks.where(pg, []any{org})
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), groupSelect+` WHERE g.org_id = $1`+cond+ks.orderLimit(pg), args...)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (groupRow, error) { return scanGroup(r) })
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	items, next := page(list, pg.Limit, func(g groupRow) pageCursor { return stringCursor(g.Name, g.ID.String()) })
	return envelope(c, items, next, total, false)
}

func (rt *alertsRuntime) getGroup(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var g groupRow
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if g, err = scanGroup(tx.QueryRow(c.Context(), groupSelect+` WHERE g.org_id = $1 AND g.id = $2`, org, id)); err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(),
			`SELECT u.id, u.email, u.display_name FROM user_group_members m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.group_id = $2 ORDER BY u.email`, org, id)
		if err != nil {
			return err
		}
		g.Members, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (groupMember, error) {
			var m groupMember
			return m, r.Scan(&m.UserID, &m.Email, &m.DisplayName)
		})
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	if g.Members == nil {
		g.Members = []groupMember{}
	}
	return c.JSON(g)
}

type groupInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (in *groupInput) apply(g *groupRow) error {
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		g.Description = *in.Description
	}
	if g.Name == "" || utf8.RuneCountInString(g.Name) > 100 {
		return errors.New("name is required (at most 100 characters)")
	}
	if utf8.RuneCountInString(g.Description) > 500 {
		return errors.New("description is at most 500 characters")
	}
	return nil
}

func (rt *alertsRuntime) createGroup(c *fiber.Ctx) error {
	org := orgID(c)
	var in groupInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	g := groupRow{ID: uuid.New(), MemberIDs: []uuid.UUID{}}
	if err := in.apply(&g); err != nil {
		return badRequest(c, err.Error())
	}
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(c.Context(),
			`INSERT INTO user_groups (id, org_id, name, description) VALUES ($1, $2, $3, $4) RETURNING created_at, updated_at`,
			g.ID, org, g.Name, g.Description).Scan(&g.CreatedAt, &g.UpdatedAt)
	})
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.group.created", g.Name, map[string]any{"id": g.ID})
	return c.Status(201).JSON(g)
}

func (rt *alertsRuntime) updateGroup(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var in groupInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	var g groupRow
	var invalid error
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if g, err = scanGroup(tx.QueryRow(c.Context(), groupSelect+` WHERE g.org_id = $1 AND g.id = $2 FOR UPDATE OF g`, org, id)); err != nil {
			return err
		}
		if invalid = in.apply(&g); invalid != nil {
			return nil
		}
		return tx.QueryRow(c.Context(),
			`UPDATE user_groups SET name = $3, description = $4, updated_at = NOW() WHERE org_id = $1 AND id = $2 RETURNING updated_at`,
			org, id, g.Name, g.Description).Scan(&g.UpdatedAt)
	})
	if invalid != nil {
		return badRequest(c, invalid.Error())
	}
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.group.updated", g.Name, map[string]any{"id": g.ID})
	return c.JSON(g)
}

func (rt *alertsRuntime) deleteGroup(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var name string
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(), `DELETE FROM user_groups WHERE org_id = $1 AND id = $2 RETURNING name`, org, id).
			Scan(&name); err != nil {
			return err
		}
		// Rules keep only recipients that exist.
		_, err := tx.Exec(c.Context(),
			`UPDATE alert_rules SET recipients = jsonb_set(recipients, '{group_ids}',
			   COALESCE((SELECT jsonb_agg(x) FROM jsonb_array_elements(recipients->'group_ids') x WHERE x <> to_jsonb($2::text)), '[]'))
			 WHERE org_id = $1 AND recipients->'group_ids' ? $2::text`, org, id.String())
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.group.deleted", name, map[string]any{"id": id})
	return c.SendStatus(204)
}

// putGroupMembers replaces the members; every user must be an org member.
func (rt *alertsRuntime) putGroupMembers(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var in struct {
		UserIDs []uuid.UUID `json:"user_ids"`
	}
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	users := uniqueIDs(in.UserIDs)
	if len(users) > 1000 {
		return badRequest(c, "at most 1000 members")
	}
	var g groupRow
	var invalid error
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if _, err := scanGroup(tx.QueryRow(c.Context(), groupSelect+` WHERE g.org_id = $1 AND g.id = $2 FOR UPDATE OF g`, org, id)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM org_memberships WHERE org_id = $1 AND user_id = ANY($2)`,
			org, users).Scan(&n); err != nil {
			return err
		}
		if n != len(users) {
			invalid = errors.New("user_ids must be members of this organization")
			return nil
		}
		if _, err := tx.Exec(c.Context(), `DELETE FROM user_group_members WHERE org_id = $1 AND group_id = $2 AND NOT (user_id = ANY($3))`,
			org, id, users); err != nil {
			return err
		}
		if _, err := tx.Exec(c.Context(),
			`INSERT INTO user_group_members (org_id, group_id, user_id) SELECT $1, $2, u FROM unnest($3::uuid[]) u
			 ON CONFLICT DO NOTHING`, org, id, users); err != nil {
			return err
		}
		if _, err := tx.Exec(c.Context(), `UPDATE user_groups SET updated_at = NOW() WHERE id = $1`, id); err != nil {
			return err
		}
		g, err = scanGroup(tx.QueryRow(c.Context(), groupSelect+` WHERE g.org_id = $1 AND g.id = $2`, org, id))
		return err
	})
	if invalid != nil {
		return badRequest(c, invalid.Error())
	}
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.group.members_set", g.Name, map[string]any{"id": id, "members": len(users)})
	return c.JSON(g)
}

// ── Alert history and deliveries ────────────────────────────────────────────

type alertView struct {
	ID         uuid.UUID         `json:"id"`
	RuleID     *uuid.UUID        `json:"rule_id"`
	RuleName   string            `json:"rule_name"`
	DedupeKey  string            `json:"dedupe_key"`
	Group      map[string]string `json:"group"`
	ProjectID  *uuid.UUID        `json:"project_id"`
	State      string            `json:"state"`
	Severity   string            `json:"severity"`
	FirstAt    time.Time         `json:"first_at"`
	LastAt     time.Time         `json:"last_at"`
	Count      int               `json:"count"`
	ResolvedAt *time.Time        `json:"resolved_at"`
	SampleIDs  []uuid.UUID       `json:"sample_event_ids"`
	Suppressed bool              `json:"suppressed"`
	Test       bool              `json:"test"`
	Samples    []map[string]any  `json:"samples,omitempty"`
	Deliveries map[string]int    `json:"deliveries,omitempty"`
	CreatedAt  time.Time         `json:"-"`
}

const alertSelect = `SELECT id, rule_id, rule_name, dedupe_key, group_values, project_id, state, severity::text, first_at,
	last_at, count, resolved_at, sample_event_ids, suppressed, test FROM alerts`

func scanAlert(r pgx.Row) (alertView, error) {
	var a alertView
	var group []byte
	err := r.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.DedupeKey, &group, &a.ProjectID, &a.State, &a.Severity, &a.FirstAt,
		&a.LastAt, &a.Count, &a.ResolvedAt, &a.SampleIDs, &a.Suppressed, &a.Test)
	_ = json.Unmarshal(group, &a.Group)
	if a.Group == nil {
		a.Group = map[string]string{}
	}
	return a, err
}

func (rt *alertsRuntime) listAlerts(c *fiber.Ctx) error {
	org := orgID(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "last_at", id: "id", desc: true}
	args := []any{org}
	filter := ""
	switch s := c.Query("state"); s {
	case "":
	case "firing", "resolved":
		args = append(args, s)
		filter += fmt.Sprintf(" AND state = $%d", len(args))
	default:
		return badRequest(c, "state must be firing or resolved")
	}
	if r := c.Query("rule_id"); r != "" {
		id, err := uuid.Parse(r)
		if err != nil {
			return badRequest(c, "invalid rule_id")
		}
		args = append(args, id)
		filter += fmt.Sprintf(" AND rule_id = $%d", len(args))
	}
	var list []alertView
	var total int64
	var capped bool
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if total, capped, err = cappedCount(c.Context(), tx, `FROM alerts WHERE org_id = $1`+filter, args); err != nil {
			return err
		}
		cond, qargs, err := ks.where(pg, args)
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), alertSelect+` WHERE org_id = $1`+filter+cond+ks.orderLimit(pg), qargs...)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alertView, error) { return scanAlert(r) })
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	items, next := page(list, pg.Limit, func(a alertView) pageCursor { return timeCursor(a.LastAt, a.ID.String()) })
	return envelope(c, items, next, total, capped)
}

func (rt *alertsRuntime) getAlert(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var a alertView
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if a, err = scanAlert(tx.QueryRow(c.Context(), alertSelect+` WHERE org_id = $1 AND id = $2`, org, id)); err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(),
			`SELECT id, type, severity::text, occurred_at, attrs FROM events WHERE org_id = $1 AND id = ANY($2)
			 ORDER BY occurred_at DESC`, org, a.SampleIDs)
		if err != nil {
			return err
		}
		a.Samples, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (map[string]any, error) {
			var ev events.Event
			var raw []byte
			if err := r.Scan(&ev.ID, &ev.Type, &ev.Severity, &ev.OccurredAt, &raw); err != nil {
				return nil, err
			}
			var attrs map[string]any
			_ = json.Unmarshal(raw, &attrs)
			return map[string]any{"event_id": ev.ID, "type": ev.Type, "severity": ev.Severity, "occurred_at": ev.OccurredAt,
				"attrs": alerts.SafeAttrs(attrs)}, nil
		})
		if err != nil {
			return err
		}
		a.Deliveries = map[string]int{}
		drows, err := tx.Query(c.Context(), `SELECT state, count(*) FROM notification_outbox WHERE org_id = $1 AND alert_id = $2 GROUP BY state`, org, id)
		if err != nil {
			return err
		}
		for drows.Next() {
			var s string
			var n int
			if err := drows.Scan(&s, &n); err != nil {
				drows.Close()
				return err
			}
			a.Deliveries[s] = n
		}
		drows.Close()
		return drows.Err()
	})
	if err != nil {
		return channelError(c, err)
	}
	if a.Samples == nil {
		a.Samples = []map[string]any{}
	}
	return c.JSON(a)
}

type deliveryView struct {
	ID            uuid.UUID  `json:"id"`
	AlertID       *uuid.UUID `json:"alert_id"`
	RuleID        *uuid.UUID `json:"rule_id"`
	RuleName      *string    `json:"rule_name"`
	ChannelKind   string     `json:"channel_kind"`
	ChannelID     *uuid.UUID `json:"channel_id"`
	ChannelName   *string    `json:"channel_name"`
	UserID        *uuid.UUID `json:"user_id"`
	Target        string     `json:"target"`
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastError     *string    `json:"last_error"`
	LastStatus    *int       `json:"last_status"`
	RemoteID      *string    `json:"remote_id"`
	CreatedAt     time.Time  `json:"created_at"`
	SentAt        *time.Time `json:"sent_at"`
}

func (rt *alertsRuntime) listDeliveries(c *fiber.Ctx) error {
	org := orgID(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "created_at", id: "id", desc: true}
	args := []any{org}
	filter := ""
	if s := c.Query("state"); s != "" {
		if !strings.Contains("|pending|sending|sent|failed|dead|", "|"+s+"|") {
			return badRequest(c, "state must be pending, sending, sent, failed or dead")
		}
		args = append(args, s)
		filter += fmt.Sprintf(" AND state = $%d", len(args))
	}
	if k := c.Query("channel_kind"); k != "" {
		args = append(args, k)
		filter += fmt.Sprintf(" AND channel_kind = $%d", len(args))
	}
	if r := c.Query("rule_id"); r != "" {
		id, err := uuid.Parse(r)
		if err != nil {
			return badRequest(c, "invalid rule_id")
		}
		args = append(args, id)
		filter += fmt.Sprintf(" AND rule_id = $%d", len(args))
	}
	var list []deliveryView
	var total int64
	var capped bool
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if total, capped, err = cappedCount(c.Context(), tx, `FROM notification_deliveries WHERE org_id = $1`+filter, args); err != nil {
			return err
		}
		cond, qargs, err := ks.where(pg, args)
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(),
			`SELECT id, alert_id, rule_id, rule_name, channel_kind, channel_id, channel_name, user_id, target, state, attempts,
			        next_attempt_at, last_error, last_status, remote_id, created_at, sent_at
			 FROM notification_deliveries WHERE org_id = $1`+filter+cond+ks.orderLimit(pg), qargs...)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (deliveryView, error) {
			var d deliveryView
			return d, r.Scan(&d.ID, &d.AlertID, &d.RuleID, &d.RuleName, &d.ChannelKind, &d.ChannelID, &d.ChannelName, &d.UserID, &d.Target,
				&d.State, &d.Attempts, &d.NextAttemptAt, &d.LastError, &d.LastStatus, &d.RemoteID, &d.CreatedAt, &d.SentAt)
		})
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	items, next := page(list, pg.Limit, func(d deliveryView) pageCursor { return timeCursor(d.CreatedAt, d.ID.String()) })
	return envelope(c, items, next, total, capped)
}

// ── Personal preferences ────────────────────────────────────────────────────

func (rt *alertsRuntime) loadPrefs(c *fiber.Ctx, tx pgx.Tx, org, user uuid.UUID) ([]alerts.Pref, error) {
	rows, err := tx.Query(c.Context(),
		`SELECT channel_kind, enabled, min_severity::text FROM user_notification_prefs WHERE org_id = $1 AND user_id = $2`, org, user)
	if err != nil {
		return nil, err
	}
	stored, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerts.Pref, error) {
		var p alerts.Pref
		return p, r.Scan(&p.ChannelKind, &p.Enabled, &p.MinSeverity)
	})
	if err != nil {
		return nil, err
	}
	out := make([]alerts.Pref, 0, len(alerts.PersonalKinds))
	for _, k := range alerts.PersonalKinds {
		p := alerts.DefaultPref(k)
		for _, s := range stored {
			if s.ChannelKind == k {
				p = s
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func (rt *alertsRuntime) getPrefs(c *fiber.Ctx) error {
	org, user := orgID(c), authUser(c)
	var out []alerts.Pref
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		var err error
		out, err = rt.loadPrefs(c, tx, org, user)
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(out)
}

func (rt *alertsRuntime) putPrefs(c *fiber.Ctx) error {
	org, user := orgID(c), authUser(c)
	var in []alerts.Pref
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	if len(in) > len(alerts.PersonalKinds) {
		return badRequest(c, "one entry per channel kind")
	}
	seen := map[string]bool{}
	for _, p := range in {
		if !strings.Contains("|telegram|slack|email|", "|"+p.ChannelKind+"|") || seen[p.ChannelKind] {
			return badRequest(c, "channel_kind must be telegram, slack or email, once each")
		}
		seen[p.ChannelKind] = true
		if !alerts.ValidSeverity(p.MinSeverity) {
			return badRequest(c, "min_severity must be info, warning or critical")
		}
	}
	var out []alerts.Pref
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		for _, p := range in {
			if _, err := tx.Exec(c.Context(),
				`INSERT INTO user_notification_prefs (user_id, org_id, channel_kind, enabled, min_severity)
				 VALUES ($1, $2, $3, $4, $5::alert_severity)
				 ON CONFLICT (org_id, user_id, channel_kind) DO UPDATE SET enabled = EXCLUDED.enabled,
				   min_severity = EXCLUDED.min_severity, updated_at = NOW()`,
				user, org, p.ChannelKind, p.Enabled, p.MinSeverity); err != nil {
				return err
			}
		}
		var err error
		out, err = rt.loadPrefs(c, tx, org, user)
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.prefs.updated", user.String(), map[string]any{"kinds": len(in)})
	return c.JSON(out)
}
