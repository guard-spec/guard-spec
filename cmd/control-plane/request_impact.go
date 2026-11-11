// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The impact preview of the request log's false-positive panel (RF-a1dbafea
// U2):
//
//	GET /organizations/:orgId/requests/:requestId/impact
//
// Before an admin adds an allow exemplar for a refused request, or files a
// false-positive report, the panel says how many recent requests the change
// concerns. The control plane has neither the request text (unless the org
// stores it, behind its own permission) nor the detector's models, so it
// cannot score requests again; it counts what the stored scores and hashes
// tell, over the last 7 days, and says which part is exact:
//
//   - same_input: requests with the identical body (request_sha256), and how
//     many were refused. An allow exemplar of this text lowers their L3
//     score like this one's.
//   - same_rule: when a policy rule refused the request, the requests that
//     rule decided. An exemplar does not change a rule's decision: the rule
//     must change.
//   - threshold: when the detector refused it, the detector's refusals with
//     a score at or below this one: what raising the org's block threshold
//     just above this score would let through (exact, from stored scores),
//     unless the score is at or above the gateway's own threshold, which the
//     org setting can only lower.
//
// Counts only, never content; whoever may read the request log may read it.

// impactWindow is how far back the preview counts.
const impactWindow = 7 * 24 * time.Hour

// gatewayDefaultThreshold is the gateway's INJECTION_THRESHOLD default; an
// org's injection_threshold only counts below it.
const gatewayDefaultThreshold = 0.85

type impactCount struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

type impactThreshold struct {
	// Org is the org's injection_threshold; null: the gateway's applies.
	Org            *float64 `json:"org"`
	GatewayDefault float64  `json:"gateway_default"`
	// AboveDefault: the score is at or above the gateway's default
	// threshold, so no org setting lets the request through.
	AboveDefault bool `json:"above_default"`
	// AtOrBelow counts the detector's refusals with a score at or below
	// this request's, this one included.
	AtOrBelow int64 `json:"at_or_below"`
}

type requestImpact struct {
	Window  string    `json:"window"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Request struct {
		ID     uuid.UUID `json:"id"`
		Action string    `json:"action"`
		// DecidedBy: rule (a policy rule), detector (the injection score),
		// input (the input settings or unscanned parts), none (not refused).
		DecidedBy      string     `json:"decided_by"`
		InjectionScore float64    `json:"injection_score"`
		InjectionLabel *string    `json:"injection_label"`
		RuleID         *uuid.UUID `json:"rule_id"`
		HasHash        bool       `json:"has_hash"`
	} `json:"request"`
	SameInput *impactCount     `json:"same_input"`
	SameRule  *impactCount     `json:"same_rule"`
	Threshold *impactThreshold `json:"threshold"`
}

// decidedBy tells what refused a request row.
func decidedBy(action string, rule *uuid.UUID, label *string, tags []string) string {
	if action != "block" {
		return "none"
	}
	if rule != nil {
		return "rule"
	}
	l := ""
	if label != nil {
		l = strings.ToLower(strings.TrimSpace(*label))
	}
	if l == "unscanned_content" {
		return "input"
	}
	for _, t := range tags {
		if strings.HasPrefix(t, "input:refused=") || (l == "" && strings.HasPrefix(t, "input:unscanned_")) {
			return "input"
		}
	}
	return "detector"
}

var errImpactNotFound = errors.New("request not found")

func loadImpact(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, out *requestImpact) error {
	var (
		hash  *string
		tags  []string
		score float32
	)
	err := tx.QueryRow(ctx,
		`SELECT action, rule_id, injection_label, COALESCE(injection_score, 0), request_sha256, COALESCE(pii_entities, '{}')
		 FROM requests WHERE org_id = $1 AND id = $2`, org, id).
		Scan(&out.Request.Action, &out.Request.RuleID, &out.Request.InjectionLabel, &score, &hash, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return errImpactNotFound
	}
	if err != nil {
		return err
	}
	out.Request.ID = id
	out.Request.InjectionScore = float64(score)
	out.Request.HasHash = hash != nil && *hash != ""
	out.Request.DecidedBy = decidedBy(out.Request.Action, out.Request.RuleID, out.Request.InjectionLabel, tags)

	if out.Request.HasHash {
		var c impactCount
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE action = 'block') FROM requests
			 WHERE org_id = $1 AND created_at >= $2 AND request_sha256 = $3`, org, out.From, *hash).
			Scan(&c.Total, &c.Blocked); err != nil {
			return err
		}
		out.SameInput = &c
	}
	switch out.Request.DecidedBy {
	case "rule":
		var c impactCount
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE action = 'block') FROM requests
			 WHERE org_id = $1 AND created_at >= $2 AND rule_id = $3`, org, out.From, *out.Request.RuleID).
			Scan(&c.Total, &c.Blocked); err != nil {
			return err
		}
		out.SameRule = &c
	case "detector":
		th := impactThreshold{GatewayDefault: gatewayDefaultThreshold, AboveDefault: float64(score) >= gatewayDefaultThreshold}
		if err := tx.QueryRow(ctx,
			`SELECT (guard_settings->>'injection_threshold')::float8 FROM organizations WHERE id = $1`, org).Scan(&th.Org); err != nil {
			return err
		}
		// The detector's refusals: no rule, a label other than the input
		// codes (a refused input is stored without a label).
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM requests
			 WHERE org_id = $1 AND created_at >= $2 AND action = 'block' AND rule_id IS NULL
			   AND injection_label IS NOT NULL AND lower(injection_label) <> 'unscanned_content'
			   AND COALESCE(injection_score, 0) <= $3`, org, out.From, score).Scan(&th.AtOrBelow); err != nil {
			return err
		}
		out.Threshold = &th
	}
	return nil
}

func getRequestImpact(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("requestId"))
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "request not found"})
		}
		out := requestImpact{Window: "7d", To: time.Now().UTC()}
		out.From = out.To.Add(-impactWindow)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return loadImpact(c.Context(), tx, org, id, &out)
		})
		if errors.Is(err, errImpactNotFound) {
			return c.Status(404).JSON(fiber.Map{"error": "request not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}
