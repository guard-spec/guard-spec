// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/giaplee/guard-spec/internal/alerts"
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errDuplicateName = errors.New("the name is already used in this organization")

// refError is a reference to something outside the org (400).
type refError struct{ msg string }

func (e *refError) Error() string { return e.msg }

func ruleError(c *fiber.Ctx, err error) error {
	var ve *alerts.ValidationError
	var re *refError
	switch {
	case errors.As(err, &ve):
		out := fiber.Map{"error": ve.Message}
		if ve.Position != nil {
			out["position"] = *ve.Position
		}
		return c.Status(400).JSON(out)
	case errors.As(err, &re):
		return badRequest(c, re.msg)
	case errors.Is(err, errDuplicateName) || isUniqueViolation(err):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": errDuplicateName.Error()})
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, alerts.ErrNoRule):
		return notFound(c)
	case isPageError(err):
		return badPage(c, err)
	}
	return serverError(c, err)
}

func uniqueIDs(ids []uuid.UUID) []uuid.UUID {
	out := []uuid.UUID{}
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// checkRuleRefs refuses recipients and channels outside org: users who are
// not members, groups and channels of another org.
func checkRuleRefs(ctx context.Context, tx pgx.Tx, org uuid.UUID, r *alerts.Rule) error {
	r.Recipients.UserIDs = uniqueIDs(r.Recipients.UserIDs)
	r.Recipients.GroupIDs = uniqueIDs(r.Recipients.GroupIDs)
	r.ChannelIDs = uniqueIDs(r.ChannelIDs)
	count := func(q string, ids []uuid.UUID) (int, error) {
		var n int
		err := tx.QueryRow(ctx, q, org, ids).Scan(&n)
		return n, err
	}
	checks := []struct {
		q    string
		ids  []uuid.UUID
		what string
	}{
		{`SELECT count(*) FROM org_memberships WHERE org_id = $1 AND user_id = ANY($2)`, r.Recipients.UserIDs,
			"recipients.user_ids must be members of this organization"},
		{`SELECT count(*) FROM user_groups WHERE org_id = $1 AND id = ANY($2)`, r.Recipients.GroupIDs,
			"recipients.group_ids must be groups of this organization"},
		{`SELECT count(*) FROM notification_channels WHERE org_id = $1 AND id = ANY($2)`, r.ChannelIDs,
			"channel_ids must be channels of this organization"},
	}
	for _, ch := range checks {
		if len(ch.ids) == 0 {
			continue
		}
		n, err := count(ch.q, ch.ids)
		if err != nil {
			return err
		}
		if n != len(ch.ids) {
			return &refError{ch.what}
		}
	}
	return nil
}

func saveRule(ctx context.Context, tx pgx.Tx, r *alerts.Rule, insert bool) error {
	quiet, err := json.Marshal(r.QuietHours)
	if err != nil {
		return err
	}
	rcpt, err := json.Marshal(r.Recipients)
	if err != nil {
		return err
	}
	if insert {
		return tx.QueryRow(ctx,
			`INSERT INTO alert_rules (id, org_id, name, enabled, event_types, condition, condition_cel, threshold,
			   window_seconds, severity, throttle_seconds, group_by, quiet_hours, auto_resolve, recipients, channel_ids, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::alert_severity,$11,$12,$13,$14,$15,$16,$17)
			 RETURNING created_at, updated_at`,
			r.ID, r.OrgID, r.Name, r.Enabled, r.EventTypes, r.Condition, r.ConditionCEL, r.Threshold, r.WindowSeconds,
			r.Severity, r.ThrottleSeconds, r.GroupBy, quiet, r.AutoResolve, rcpt, r.ChannelIDs, r.CreatedBy).
			Scan(&r.CreatedAt, &r.UpdatedAt)
	}
	return tx.QueryRow(ctx,
		`UPDATE alert_rules SET name = $3, enabled = $4, event_types = $5, condition = $6, condition_cel = $7,
		   threshold = $8, window_seconds = $9, severity = $10::alert_severity, throttle_seconds = $11, group_by = $12,
		   quiet_hours = $13, auto_resolve = $14, recipients = $15, channel_ids = $16, updated_at = NOW()
		 WHERE id = $1 AND org_id = $2 RETURNING updated_at`,
		r.ID, r.OrgID, r.Name, r.Enabled, r.EventTypes, r.Condition, r.ConditionCEL, r.Threshold, r.WindowSeconds,
		r.Severity, r.ThrottleSeconds, r.GroupBy, quiet, r.AutoResolve, rcpt, r.ChannelIDs).Scan(&r.UpdatedAt)
}

func (rt *alertsRuntime) listRules(c *fiber.Ctx) error {
	org := orgID(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "created_at", id: "id", desc: true}
	rules := []alerts.Rule{}
	var total int64
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		args := []any{org}
		filter := ""
		if q := c.Query("q"); q != "" {
			args = append(args, likePattern(q))
			filter = fmt.Sprintf(" AND name ILIKE $%d", len(args))
		}
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM alert_rules WHERE org_id = $1`+filter, args...).Scan(&total); err != nil {
			return err
		}
		cond, args, err := ks.where(pg, args)
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), `SELECT `+alerts.RuleColumns+` FROM alert_rules WHERE org_id = $1`+filter+cond+
			ks.orderLimit(pg), args...)
		if err != nil {
			return err
		}
		rules, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerts.Rule, error) { return alerts.ScanRule(r) })
		return err
	})
	if err != nil {
		return ruleError(c, err)
	}
	items, next := page(rules, pg.Limit, func(r alerts.Rule) pageCursor { return timeCursor(r.CreatedAt, r.ID.String()) })
	return envelope(c, items, next, total, false)
}

func (rt *alertsRuntime) loadRule(c *fiber.Ctx, tx pgx.Tx, org, id uuid.UUID) (alerts.Rule, error) {
	return alerts.ScanRule(tx.QueryRow(c.Context(),
		`SELECT `+alerts.RuleColumns+` FROM alert_rules WHERE org_id = $1 AND id = $2`, org, id))
}

func (rt *alertsRuntime) getRule(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var r alerts.Rule
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		r, err = rt.loadRule(c, tx, org, id)
		return err
	})
	if err != nil {
		return ruleError(c, err)
	}
	return c.JSON(r)
}

// ruleInput is what a client may set on a rule.
type ruleInput struct {
	Name            *string            `json:"name"`
	Enabled         *bool              `json:"enabled"`
	EventTypes      *[]string          `json:"event_types"`
	Condition       *string            `json:"condition"`
	Threshold       *int               `json:"threshold"`
	WindowSeconds   *int               `json:"window_seconds"`
	Severity        *string            `json:"severity"`
	ThrottleSeconds *int               `json:"throttle_seconds"`
	GroupBy         *[]string          `json:"group_by"`
	QuietHours      json.RawMessage    `json:"quiet_hours"`
	AutoResolve     *bool              `json:"auto_resolve"`
	Recipients      *alerts.Recipients `json:"recipients"`
	ChannelIDs      *[]uuid.UUID       `json:"channel_ids"`
}

// apply sets the fields present in in on r.
func (in *ruleInput) apply(r *alerts.Rule) error {
	if in.Name != nil {
		r.Name = *in.Name
	}
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	}
	if in.EventTypes != nil {
		r.EventTypes = *in.EventTypes
	}
	if in.Condition != nil {
		r.Condition = *in.Condition
	}
	if in.Threshold != nil {
		r.Threshold = *in.Threshold
	}
	if in.WindowSeconds != nil {
		r.WindowSeconds = *in.WindowSeconds
	}
	if in.Severity != nil {
		r.Severity = *in.Severity
	}
	if in.ThrottleSeconds != nil {
		r.ThrottleSeconds = *in.ThrottleSeconds
	}
	if in.GroupBy != nil {
		r.GroupBy = *in.GroupBy
	}
	if len(in.QuietHours) > 0 {
		if string(in.QuietHours) == "null" {
			r.QuietHours = nil
		} else {
			var q alerts.QuietHours
			if err := strictJSON(in.QuietHours, &q); err != nil {
				return &alerts.ValidationError{Message: "quiet_hours: " + err.Error()}
			}
			r.QuietHours = &q
		}
	}
	if in.AutoResolve != nil {
		r.AutoResolve = *in.AutoResolve
	}
	if in.Recipients != nil {
		r.Recipients = *in.Recipients
	}
	if in.ChannelIDs != nil {
		r.ChannelIDs = *in.ChannelIDs
	}
	return nil
}

func (rt *alertsRuntime) createRule(c *fiber.Ctx) error {
	org := orgID(c)
	var in ruleInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	actor := auth.UserID(c)
	r := alerts.Rule{ID: uuid.New(), OrgID: org, Enabled: true, ThrottleSeconds: alerts.DefaultThrottle, CreatedBy: &actor}
	if err := in.apply(&r); err != nil {
		return ruleError(c, err)
	}
	if err := alerts.Validate(&r); err != nil {
		return ruleError(c, err)
	}
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if err := checkRuleRefs(c.Context(), tx, org, &r); err != nil {
			return err
		}
		return saveRule(c.Context(), tx, &r, true)
	})
	if err != nil {
		return ruleError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.rule.created", r.Name, map[string]any{"id": r.ID, "severity": r.Severity})
	return c.Status(201).JSON(r)
}

func (rt *alertsRuntime) updateRule(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var in ruleInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	var r alerts.Rule
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if r, err = alerts.ScanRule(tx.QueryRow(c.Context(),
			`SELECT `+alerts.RuleColumns+` FROM alert_rules WHERE org_id = $1 AND id = $2 FOR UPDATE`, org, id)); err != nil {
			return err
		}
		if err := in.apply(&r); err != nil {
			return err
		}
		if err := alerts.Validate(&r); err != nil {
			return err
		}
		if err := checkRuleRefs(c.Context(), tx, org, &r); err != nil {
			return err
		}
		return saveRule(c.Context(), tx, &r, false)
	})
	if err != nil {
		return ruleError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.rule.updated", r.Name, map[string]any{"id": r.ID, "enabled": r.Enabled})
	return c.JSON(r)
}

func (rt *alertsRuntime) deleteRule(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var name string
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(c.Context(), `DELETE FROM alert_rules WHERE org_id = $1 AND id = $2 RETURNING name`, org, id).Scan(&name)
	})
	if err != nil {
		return ruleError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.rule.deleted", name, map[string]any{"id": id})
	return c.SendStatus(204)
}

// testRule sends a synthetic alert.test through the pipeline.
func (rt *alertsRuntime) testRule(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	alertID, err := rt.engine.FireTest(c.Context(), org, id, auth.UserID(c))
	if err != nil {
		return ruleError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.rule.tested", id.String(), map[string]any{"id": id, "alert_id": alertID})
	return c.JSON(fiber.Map{"alert_id": alertID})
}
