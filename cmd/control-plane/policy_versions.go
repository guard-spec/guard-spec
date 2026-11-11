// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Policy versions (policy_versions, migration 026): every save keeps the
// policy as it was after the save, with who saved it, when and why. The
// history is listed, two versions are compared, and a version is rolled
// back to, which is itself a new version.

// Version kinds.
const (
	versionCreate   = "create"
	versionUpdate   = "update"
	versionRollback = "rollback"
	versionConfig   = "config" // applied from the YAML file
)

// maxReasonRunes bounds the reason of a save or rollback.
const maxReasonRunes = 500

// recordPolicyVersion copies the policy's current row into policy_versions,
// in the transaction that changed it. actor uuid.Nil leaves the author
// empty (a tool running as nobody).
func recordPolicyVersion(ctx context.Context, tx pgx.Tx, org, policyID, actor uuid.UUID, kind, reason string, rolledBackTo *int) error {
	reason = strings.TrimSpace(reason)
	_, err := tx.Exec(ctx,
		`INSERT INTO policy_versions (org_id, policy_id, version, kind, name, description, project_id, enabled, log_only,
		   rules, author_id, author_email, reason, rolled_back_to)
		 SELECT p.org_id, p.id, p.version, $3, p.name, p.description, p.project_id, p.enabled, p.log_only, p.rules,
		   $4, (SELECT email FROM users WHERE id = $4), NULLIF($5, ''), $6
		 FROM policies p WHERE p.id = $1 AND p.org_id = $2`,
		policyID, org, kind, nullUUID(actor), truncateRunes(reason, maxReasonRunes), rolledBackTo)
	return err
}

// policyVersion is one row of the history as the API returns it.
type policyVersion struct {
	Version     int             `json:"version"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	ProjectID   *uuid.UUID      `json:"project_id"`
	Enabled     bool            `json:"enabled"`
	LogOnly     bool            `json:"log_only"`
	Rules       json.RawMessage `json:"rules"`
	Author      *struct {
		ID    *uuid.UUID `json:"id"`
		Email *string    `json:"email"`
	} `json:"author"`
	Reason       *string   `json:"reason"`
	RolledBackTo *int      `json:"rolled_back_to"`
	CreatedAt    time.Time `json:"created_at"`
}

// maxVersionsListed bounds one history answer: the newest first.
const maxVersionsListed = 200

func queryPolicyVersions(ctx context.Context, tx pgx.Tx, org, policyID uuid.UUID, versions []int, limit int) ([]policyVersion, error) {
	q := `SELECT version, kind, name, description, project_id, enabled, log_only, rules, author_id, author_email, reason,
	        rolled_back_to, created_at
	      FROM policy_versions WHERE org_id = $1 AND policy_id = $2`
	args := []any{org, policyID}
	if versions != nil {
		args = append(args, versions)
		q += " AND version = ANY($3)"
	}
	q += " ORDER BY version DESC"
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policyVersion{}
	for rows.Next() {
		var v policyVersion
		var authorID *uuid.UUID
		var authorEmail *string
		if err := rows.Scan(&v.Version, &v.Kind, &v.Name, &v.Description, &v.ProjectID, &v.Enabled, &v.LogOnly, &v.Rules,
			&authorID, &authorEmail, &v.Reason, &v.RolledBackTo, &v.CreatedAt); err != nil {
			return nil, err
		}
		if authorID != nil || authorEmail != nil {
			v.Author = &struct {
				ID    *uuid.UUID `json:"id"`
				Email *string    `json:"email"`
			}{authorID, authorEmail}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// policyExists reports whether the org has the policy (its current version).
func policyExists(ctx context.Context, tx pgx.Tx, org, policyID uuid.UUID) (int, bool, error) {
	var version int
	err := tx.QueryRow(ctx, `SELECT version FROM policies WHERE id = $1 AND org_id = $2`, policyID, org).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return version, err == nil, err
}

// listPolicyVersions answers GET /organizations/:orgId/policies/:id/versions:
// the newest first, with the rules of each, and the policy's current version.
func listPolicyVersions(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		var (
			items   []policyVersion
			current int
			found   bool
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if current, found, err = policyExists(c.Context(), tx, org, pID); err != nil || !found {
				return err
			}
			items, err = queryPolicyVersions(c.Context(), tx, org, pID, nil, maxVersionsListed)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if !found {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(fiber.Map{"items": items, "current": current})
	}
}

// ── Diff ──────────────────────────────────────────────────────────────────────

// fieldChange is one changed attribute of the policy between two versions.
type fieldChange struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

// ruleChange is one rule that differs: added, removed, changed (by id) or
// moved (same content, another position).
type ruleChange struct {
	Op     string       `json:"op"` // added, removed, changed, moved
	RuleID uuid.UUID    `json:"rule_id"`
	Name   string       `json:"name"`
	From   *policy.Rule `json:"from,omitempty"`
	To     *policy.Rule `json:"to,omitempty"`
	// Positions in the rule lists (0-based); -1 when the rule is not there.
	FromIndex int `json:"from_index"`
	ToIndex   int `json:"to_index"`
}

type policyDiff struct {
	From   int           `json:"from"`
	To     int           `json:"to"`
	Fields []fieldChange `json:"fields"`
	Rules  []ruleChange  `json:"rules"`
}

// sameRule compares two rules by content: name, action, target and the
// condition as canonical JSON.
func sameRule(a, b policy.Rule) bool {
	if a.Name != b.Name || a.Action != b.Action || a.RouteTarget != b.RouteTarget {
		return false
	}
	return canonicalJSON(a.Condition) == canonicalJSON(b.Condition)
}

// canonicalJSON renders raw with sorted keys and no spaces; invalid JSON
// compares as its text.
func canonicalJSON(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// diffVersions compares two versions of a policy: its fields, then its
// rules by id. The rules of from and to are given; an invalid rule list
// counts as empty.
func diffVersions(from, to policyVersion) policyDiff {
	d := policyDiff{From: from.Version, To: to.Version, Fields: []fieldChange{}, Rules: []ruleChange{}}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	if from.Name != to.Name {
		d.Fields = append(d.Fields, fieldChange{"name", from.Name, to.Name})
	}
	if str(from.Description) != str(to.Description) {
		d.Fields = append(d.Fields, fieldChange{"description", str(from.Description), str(to.Description)})
	}
	if !sameUUID(from.ProjectID, to.ProjectID) {
		d.Fields = append(d.Fields, fieldChange{"project_id", from.ProjectID, to.ProjectID})
	}
	if from.Enabled != to.Enabled {
		d.Fields = append(d.Fields, fieldChange{"enabled", from.Enabled, to.Enabled})
	}
	if from.LogOnly != to.LogOnly {
		d.Fields = append(d.Fields, fieldChange{"log_only", from.LogOnly, to.LogOnly})
	}
	var a, b []policy.Rule
	_ = json.Unmarshal(from.Rules, &a)
	_ = json.Unmarshal(to.Rules, &b)
	posB := make(map[uuid.UUID]int, len(b))
	for i, r := range b {
		posB[r.ID] = i
	}
	seen := make(map[uuid.UUID]bool, len(a))
	for i := range a {
		r := a[i]
		seen[r.ID] = true
		j, ok := posB[r.ID]
		switch {
		case !ok:
			d.Rules = append(d.Rules, ruleChange{Op: "removed", RuleID: r.ID, Name: r.Name, From: &a[i], FromIndex: i, ToIndex: -1})
		case !sameRule(r, b[j]):
			d.Rules = append(d.Rules, ruleChange{Op: "changed", RuleID: r.ID, Name: b[j].Name, From: &a[i], To: &b[j], FromIndex: i, ToIndex: j})
		case i != j:
			d.Rules = append(d.Rules, ruleChange{Op: "moved", RuleID: r.ID, Name: r.Name, FromIndex: i, ToIndex: j})
		}
	}
	for j := range b {
		if !seen[b[j].ID] {
			d.Rules = append(d.Rules, ruleChange{Op: "added", RuleID: b[j].ID, Name: b[j].Name, To: &b[j], FromIndex: -1, ToIndex: j})
		}
	}
	return d
}

// diffPolicyVersions answers GET .../policies/:id/versions/diff?from=&to=.
// Without to, the policy's current version; without from, the one before to.
func diffPolicyVersions(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		from, to := c.QueryInt("from", 0), c.QueryInt("to", 0)
		if from < 0 || to < 0 {
			return c.Status(400).JSON(fiber.Map{"error": "from and to must be version numbers"})
		}
		var (
			got   []policyVersion
			found bool
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var current int
			if current, found, err = policyExists(c.Context(), tx, org, pID); err != nil || !found {
				return err
			}
			if to == 0 {
				to = current
			}
			if from == 0 {
				from = to - 1
			}
			got, err = queryPolicyVersions(c.Context(), tx, org, pID, []int{from, to}, 0)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if !found {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		var a, b *policyVersion
		for i := range got {
			switch got[i].Version {
			case from:
				a = &got[i]
			case to:
				b = &got[i]
			}
		}
		if a == nil || b == nil {
			return c.Status(404).JSON(fiber.Map{"error": fmt.Sprintf("no version %d or %d of this policy", from, to)})
		}
		return c.JSON(diffVersions(*a, *b))
	}
}

// ── Rollback ──────────────────────────────────────────────────────────────────

var errVersionNotFound = errors.New("no such version of this policy")

// rollbackPolicy answers POST .../policies/:id/rollback with {version,
// reason}: the policy becomes what it was at version (the one before the
// current without version), as a new version. The name must still be free
// and every route target must still exist, as for any save. With two-person
// approval on, rolling an enabled policy back to a disabled version applies
// the rest and turns the disable into a request (202), as a save does.
func rollbackPolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		var req struct {
			Version int    `json:"version"`
			Reason  string `json:"reason"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}
		if req.Version < 0 {
			return c.Status(400).JSON(fiber.Map{"error": "version must be a version number"})
		}
		var (
			found        bool
			target       policyVersion
			newVersion   int
			deferDisable bool
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			// The org row lock serializes saves (checkPolicyName); the policy
			// row lock serializes rollbacks of the same policy.
			var (
				current int
				enabled bool
			)
			err := tx.QueryRow(c.Context(), `SELECT version, enabled FROM policies WHERE id = $1 AND org_id = $2 FOR UPDATE`, pID, org).
				Scan(&current, &enabled)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			found = true
			want := req.Version
			if want == 0 {
				want = current - 1
			}
			if want < 1 {
				return errVersionNotFound
			}
			got, err := queryPolicyVersions(c.Context(), tx, org, pID, []int{want}, 0)
			if err != nil {
				return err
			}
			if len(got) == 0 {
				return errVersionNotFound
			}
			target = got[0]
			var rules []policy.Rule
			if err := json.Unmarshal(target.Rules, &rules); err != nil {
				return err
			}
			// The stored rules are checked again: a field removed since, or a
			// rule the gateway cannot run, must not come back.
			for _, r := range rules {
				if err := eng.ValidateRule(&r); err != nil {
					return fmt.Errorf("%w: rule %q: %v", errRollbackInvalid, r.Name, err)
				}
			}
			if err := checkProject(c.Context(), tx, org, target.ProjectID); err != nil {
				return err
			}
			if err := checkPolicyName(c.Context(), tx, org, target.Name, pID); err != nil {
				return err
			}
			if err := checkRouteTargets(c.Context(), tx, org, routeTargets(rules)); err != nil {
				return err
			}
			if enabled && !target.Enabled {
				on, _, err := twoPersonSettings(c.Context(), tx, org)
				if err != nil {
					return err
				}
				if on {
					deferDisable = true
					target.Enabled = true
				}
			}
			if err := tx.QueryRow(c.Context(),
				`UPDATE policies SET name = $3, description = $4, project_id = $5, enabled = $6, log_only = $7, rules = $8,
				   version = version + 1, updated_at = NOW()
				 WHERE id = $1 AND org_id = $2 RETURNING version`,
				pID, org, target.Name, target.Description, target.ProjectID, target.Enabled, target.LogOnly, target.Rules).
				Scan(&newVersion); err != nil {
				return err
			}
			return recordPolicyVersion(c.Context(), tx, org, pID, auth.UserID(c), versionRollback, req.Reason, &target.Version)
		})
		var unknownTarget *unknownTargetError
		switch {
		case errors.Is(err, errVersionNotFound):
			return c.Status(404).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, errRollbackInvalid), errors.Is(err, errUnknownProject), errors.As(err, &unknownTarget):
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, errDuplicatePolicyName):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		case err != nil:
			return serverError(c, err)
		case !found:
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		logActivity(c, db, &org, "policy.rolled_back", pID.String(), map[string]any{
			"id": pID, "to_version": target.Version, "version": newVersion, "reason": strings.TrimSpace(req.Reason)})
		if deferDisable {
			return requestApproval(c, db, org, approvalPolicyDisable, pID.String(),
				map[string]any{"enabled": false, "rolled_back_to": target.Version}, req.Reason)
		}
		return c.JSON(fiber.Map{"id": pID, "version": newVersion, "rolled_back_to": target.Version})
	}
}

var errRollbackInvalid = errors.New("that version cannot run on this gateway")
