// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two-person approval (approval_requests, migration 027). With the org's
// two_person_approval on, four changes do not take effect when asked for:
// disabling a policy, deleting a policy, turning on the storage of prompt
// and answer content, and deleting the organization. The handler records a
// pending request and answers 202 with it; another admin approves it, which
// applies the change in the same transaction, or rejects it. A request
// nobody decides within approval_expiry_hours expires. Every step is in the
// activity log (approval.requested, approval.approved, approval.rejected)
// and, through it, in the alert events (activity.approval.*).

const (
	approvalPolicyDisable  = "policy.disable"
	approvalPolicyDelete   = "policy.delete"
	approvalContentStorage = "content_storage.enable"
	approvalOrgDelete      = "org.delete"

	defaultApprovalExpiryHours = 24
	maxApprovalExpiryHours     = 720
	maxApprovalNoteRunes       = 500
)

// approvalKinds names every request kind, for validation and the docs.
var approvalKinds = []string{approvalPolicyDisable, approvalPolicyDelete, approvalContentStorage, approvalOrgDelete}

// twoPersonSettings reads the org's two-person approval settings: whether
// it is on and how many hours a request lives.
func twoPersonSettings(ctx context.Context, tx pgx.Tx, org uuid.UUID) (on bool, hours int, err error) {
	err = tx.QueryRow(ctx, `SELECT two_person_approval, approval_expiry_hours FROM org_security WHERE org_id = $1`, org).
		Scan(&on, &hours)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, defaultApprovalExpiryHours, nil
	}
	return on, hours, err
}

// twoPersonOn says whether the org requires a second admin for guarded changes.
func twoPersonOn(ctx context.Context, db *pgxpool.Pool, org uuid.UUID) (bool, error) {
	var on bool
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		var err error
		on, _, err = twoPersonSettings(ctx, tx, org)
		return err
	})
	return on, err
}

type approvalActor struct {
	ID    *uuid.UUID `json:"id"`
	Email *string    `json:"email"`
}

// approvalRequest is one row as the API returns it.
type approvalRequest struct {
	ID     uuid.UUID `json:"id"`
	Kind   string    `json:"kind"`
	Target *string   `json:"target"`
	// TargetLabel names a policy target (its name) while it exists.
	TargetLabel  *string         `json:"target_label,omitempty"`
	Payload      json.RawMessage `json:"payload"`
	Reason       *string         `json:"reason"`
	Status       string          `json:"status"`
	RequestedBy  *approvalActor  `json:"requested_by"`
	DecidedBy    *approvalActor  `json:"decided_by"`
	DecidedAt    *time.Time      `json:"decided_at"`
	DecisionNote *string         `json:"decision_note"`
	ExpiresAt    time.Time       `json:"expires_at"`
	CreatedAt    time.Time       `json:"created_at"`
}

const approvalColumns = `a.id, a.kind, a.target, p.name, a.payload, a.reason, a.status, a.requested_by, a.requested_by_email,
	a.decided_by, a.decided_by_email, a.decided_at, a.decision_note, a.expires_at, a.created_at`

const approvalFrom = ` FROM approval_requests a
	LEFT JOIN policies p ON a.kind LIKE 'policy.%' AND p.org_id = a.org_id AND p.id::text = a.target`

func scanApproval(row pgx.Row) (approvalRequest, error) {
	var r approvalRequest
	var reqID, decID *uuid.UUID
	var reqEmail, decEmail *string
	err := row.Scan(&r.ID, &r.Kind, &r.Target, &r.TargetLabel, &r.Payload, &r.Reason, &r.Status, &reqID, &reqEmail,
		&decID, &decEmail, &r.DecidedAt, &r.DecisionNote, &r.ExpiresAt, &r.CreatedAt)
	if err != nil {
		return r, err
	}
	if reqID != nil || reqEmail != nil {
		r.RequestedBy = &approvalActor{reqID, reqEmail}
	}
	if decID != nil || decEmail != nil {
		r.DecidedBy = &approvalActor{decID, decEmail}
	}
	return r, nil
}

// expireApprovals marks the org's pending requests past their time.
func expireApprovals(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx,
		`UPDATE approval_requests SET status = 'expired' WHERE org_id = $1 AND status = 'pending' AND expires_at <= NOW()`, org)
	return err
}

// requestApproval records a pending request of the caller and answers 202
// with it. reason is the requester's; target a policy id or the org id.
func requestApproval(c *fiber.Ctx, db *pgxpool.Pool, org uuid.UUID, kind, target string, payload map[string]any, reason string) error {
	raw, err := json.Marshal(payload)
	if err != nil || payload == nil {
		raw = []byte("{}")
	}
	reason = truncateRunes(strings.TrimSpace(reason), maxApprovalNoteRunes)
	var out approvalRequest
	err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
		_, hours, err := twoPersonSettings(c.Context(), tx, org)
		if err != nil {
			return err
		}
		var id uuid.UUID
		if err := tx.QueryRow(c.Context(),
			`INSERT INTO approval_requests (org_id, kind, target, payload, reason, requested_by, requested_by_email, expires_at)
			 VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), $6, (SELECT email FROM users WHERE id = $6),
			   NOW() + make_interval(hours => $7))
			 RETURNING id`,
			org, kind, target, raw, reason, nullUUID(auth.UserID(c)), hours).Scan(&id); err != nil {
			return err
		}
		out, err = scanApproval(tx.QueryRow(c.Context(), `SELECT `+approvalColumns+approvalFrom+` WHERE a.id = $1`, id))
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	logActivity(c, db, &org, "approval.requested", target, map[string]any{
		"approval_id": out.ID, "kind": kind, "reason": reason, "expires_at": out.ExpiresAt})
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"approval_required": true, "request": out})
}

// listApprovals answers GET /organizations/:orgId/approvals?status=pending
// (the default; all, approved, rejected or expired), newest first.
func listApprovals(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		status := c.Query("status", "pending")
		switch status {
		case "pending", "approved", "rejected", "expired", "all":
		default:
			return c.Status(400).JSON(fiber.Map{"error": "status must be pending, approved, rejected, expired or all"})
		}
		items := []approvalRequest{}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := expireApprovals(c.Context(), tx, org); err != nil {
				return err
			}
			args := []any{org}
			filter := ""
			if status != "all" {
				args = append(args, status)
				filter = " AND a.status = $2"
			}
			rows, err := tx.Query(c.Context(),
				`SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id = $1`+filter+` ORDER BY a.created_at DESC, a.id DESC LIMIT 200`, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				r, err := scanApproval(rows)
				if err != nil {
					return err
				}
				items = append(items, r)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"items": items})
	}
}

var (
	errApprovalNotPending = errors.New("this request is no longer pending")
	errApprovalExpired    = errors.New("this request has expired")
	errSelfApproval       = errors.New("the admin who asked for a change cannot approve it")
	errApprovalTargetGone = errors.New("what the request is about no longer exists")
)

// decideApproval loads a pending request for update, or says why not.
func decideApproval(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (approvalRequest, error) {
	r, err := scanApproval(tx.QueryRow(ctx,
		`SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE OF a`, org, id))
	if err != nil {
		return r, err
	}
	if r.Status != "pending" {
		return r, errApprovalNotPending
	}
	if !r.ExpiresAt.After(time.Now()) {
		_, _ = tx.Exec(ctx, `UPDATE approval_requests SET status = 'expired' WHERE id = $1`, id)
		return r, errApprovalExpired
	}
	return r, nil
}

// applyApproval makes the approved change, as the approver.
func applyApproval(ctx context.Context, tx pgx.Tx, org uuid.UUID, r approvalRequest, approver uuid.UUID) error {
	target := ""
	if r.Target != nil {
		target = *r.Target
	}
	switch r.Kind {
	case approvalContentStorage:
		_, err := tx.Exec(ctx, `UPDATE organizations SET audit_store_content = true, updated_at = NOW() WHERE id = $1`, org)
		return err
	case approvalPolicyDisable:
		pID, err := uuid.Parse(target)
		if err != nil {
			return errApprovalTargetGone
		}
		tag, err := tx.Exec(ctx,
			`UPDATE policies SET enabled = false, version = version + 1, updated_at = NOW() WHERE id = $1 AND org_id = $2`, pID, org)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errApprovalTargetGone
		}
		return recordPolicyVersion(ctx, tx, org, pID, approver, versionUpdate, "disabled by approved request "+r.ID.String(), nil)
	case approvalPolicyDelete:
		pID, err := uuid.Parse(target)
		if err != nil {
			return errApprovalTargetGone
		}
		tag, err := tx.Exec(ctx, `DELETE FROM policies WHERE id = $1 AND org_id = $2`, pID, org)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errApprovalTargetGone
		}
		return nil
	case approvalOrgDelete:
		return deleteOrgRows(ctx, tx, org)
	}
	return fmt.Errorf("unknown approval kind %q", r.Kind)
}

// deleteOrgRows removes the organization and everything it owns. Audit rows
// do not cascade (migration 001), so they go first.
func deleteOrgRows(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM requests WHERE org_id = $1`, org); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errApprovalTargetGone
	}
	return nil
}

// effectAction is the activity log action of an applied request.
func effectAction(kind string) string {
	switch kind {
	case approvalContentStorage:
		return "org.settings_changed"
	case approvalPolicyDisable:
		return "policy.updated"
	case approvalPolicyDelete:
		return "policy.deleted"
	case approvalOrgDelete:
		return "org.deleted"
	}
	return "approval.applied"
}

// approveRequest answers POST .../approvals/:id/approve {note}: another
// admin than the requester applies the change.
func approveRequest(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request id"})
		}
		note, err := decisionNote(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		actor := auth.UserID(c)
		var r approvalRequest
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if r, err = decideApproval(c.Context(), tx, org, id); err != nil {
				return err
			}
			if r.RequestedBy != nil && r.RequestedBy.ID != nil && *r.RequestedBy.ID == actor {
				return errSelfApproval
			}
			if err := applyApproval(c.Context(), tx, org, r, actor); err != nil {
				if errors.Is(err, errApprovalTargetGone) {
					_, _ = tx.Exec(c.Context(), `UPDATE approval_requests SET status = 'expired' WHERE id = $1`, id)
				}
				return err
			}
			if r.Kind == approvalOrgDelete {
				return nil // the row went with the organization
			}
			_, err = tx.Exec(c.Context(),
				`UPDATE approval_requests SET status = 'approved', decided_by = $2, decided_by_email = (SELECT email FROM users WHERE id = $2),
				   decided_at = NOW(), decision_note = NULLIF($3, '') WHERE id = $1`, id, nullUUID(actor), note)
			return err
		})
		if status, msg := approvalError(err); status != 0 {
			return c.Status(status).JSON(fiber.Map{"error": msg, "code": approvalCode(err)})
		}
		if err != nil {
			return serverError(c, err)
		}
		details := map[string]any{"approval_id": id, "kind": r.Kind, "note": note, "requested_by": r.RequestedBy}
		target := ""
		if r.Target != nil {
			target = *r.Target
		}
		if r.Kind == approvalOrgDelete {
			// The org's log went with it: the instance log keeps the trace.
			writeActivity(c.Context(), db, activityEntry{ActorID: actor, Action: "org.deleted", Target: org.String(), IP: clientIP(c),
				Details: details})
			slog.Info("organization deleted", "org", org, "by", actor, "approval", id)
			return c.Status(204).Send(nil)
		}
		logActivity(c, db, &org, "approval.approved", target, details)
		logActivity(c, db, &org, effectAction(r.Kind), target, map[string]any{"approval_id": id, "kind": r.Kind})
		out, err := loadApproval(c.Context(), db, org, id)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}

// rejectRequest answers POST .../approvals/:id/reject {note}. The requester
// may reject their own request (withdraw it).
func rejectRequest(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request id"})
		}
		note, err := decisionNote(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		actor := auth.UserID(c)
		var r approvalRequest
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if r, err = decideApproval(c.Context(), tx, org, id); err != nil {
				return err
			}
			_, err = tx.Exec(c.Context(),
				`UPDATE approval_requests SET status = 'rejected', decided_by = $2, decided_by_email = (SELECT email FROM users WHERE id = $2),
				   decided_at = NOW(), decision_note = NULLIF($3, '') WHERE id = $1`, id, nullUUID(actor), note)
			return err
		})
		if status, msg := approvalError(err); status != 0 {
			return c.Status(status).JSON(fiber.Map{"error": msg, "code": approvalCode(err)})
		}
		if err != nil {
			return serverError(c, err)
		}
		target := ""
		if r.Target != nil {
			target = *r.Target
		}
		logActivity(c, db, &org, "approval.rejected", target, map[string]any{"approval_id": id, "kind": r.Kind, "note": note})
		out, err := loadApproval(c.Context(), db, org, id)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}

func loadApproval(ctx context.Context, db *pgxpool.Pool, org, id uuid.UUID) (approvalRequest, error) {
	var out approvalRequest
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		var err error
		out, err = scanApproval(tx.QueryRow(ctx, `SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id = $1 AND a.id = $2`, org, id))
		return err
	})
	return out, err
}

// decisionNote reads the optional {note} of a decision.
func decisionNote(c *fiber.Ctx) (string, error) {
	var req struct {
		Note string `json:"note"`
	}
	if len(c.Body()) > 0 {
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return "", errors.New("invalid body")
		}
	}
	req.Note = strings.TrimSpace(req.Note)
	if len([]rune(req.Note)) > maxApprovalNoteRunes {
		return "", fmt.Errorf("note must be at most %d characters", maxApprovalNoteRunes)
	}
	return req.Note, nil
}

// approvalError maps a decision's refusal to a status, or 0 for none.
func approvalError(err error) (int, string) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return fiber.StatusNotFound, "not found"
	case errors.Is(err, errApprovalNotPending), errors.Is(err, errApprovalExpired), errors.Is(err, errApprovalTargetGone):
		return fiber.StatusConflict, err.Error()
	case errors.Is(err, errSelfApproval):
		return fiber.StatusForbidden, err.Error()
	}
	return 0, ""
}

func approvalCode(err error) string {
	switch {
	case errors.Is(err, errApprovalNotPending):
		return "approval_not_pending"
	case errors.Is(err, errApprovalExpired):
		return "approval_expired"
	case errors.Is(err, errApprovalTargetGone):
		return "approval_target_gone"
	case errors.Is(err, errSelfApproval):
		return "self_approval"
	}
	return ""
}

// deleteOrg answers DELETE /organizations/:orgId {confirm: <slug>} (owner):
// the organization and everything it owns go, at once or, with two-person
// approval, once another admin approves. The default organization (the
// instance's first, migration 002) is never deleted.
func deleteOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Confirm string `json:"confirm"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "confirm (the organization's slug) is required"})
		}
		if org == defaultOrgID {
			return auth.Deny(c, fiber.StatusConflict, "default_org", "the default organization cannot be deleted")
		}
		var slug string
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(), `SELECT slug FROM organizations WHERE id = $1`, org).Scan(&slug)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		if req.Confirm != slug {
			return auth.Deny(c, fiber.StatusBadRequest, "confirm_mismatch", "confirm must be the organization's slug ("+slug+")")
		}
		on, err := twoPersonOn(c.Context(), db, org)
		if err != nil {
			return serverError(c, err)
		}
		if on {
			return requestApproval(c, db, org, approvalOrgDelete, org.String(), map[string]any{"slug": slug}, req.Reason)
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return deleteOrgRows(c.Context(), tx, org)
		})
		if err != nil {
			return serverError(c, err)
		}
		actor := auth.UserID(c)
		writeActivity(c.Context(), db, activityEntry{ActorID: actor, Action: "org.deleted", Target: org.String(), IP: clientIP(c),
			Details: map[string]any{"slug": slug, "reason": strings.TrimSpace(req.Reason)}})
		slog.Info("organization deleted", "org", org, "slug", slug, "by", actor)
		return c.Status(204).Send(nil)
	}
}
