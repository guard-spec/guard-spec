// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two-person approval (approval_requests, migrations 027 and 029).
//
// With the org's two_person_approval on, two changes do not take effect
// when asked for: disabling a policy and turning on the storage of prompt
// and answer content. Deleting the organization always waits, whatever the
// setting: an owner asks, and another owner or an instance administrator
// approves (an instance administrator may also delete it at once, giving a
// reason). The handler records a pending request and answers 202 with it;
// asking again while one is pending answers with that one (one pending
// request per org, kind and target, a unique index). Another admin than
// the requester approves it, which applies the change in the same
// transaction under row locks, or rejects it. A request nobody decides
// within approval_expiry_hours expires; one whose target is gone or already
// done (the policy was deleted or is already disabled) is cancelled.
//
// Deleting a policy needs no approval: only a disabled policy can be
// deleted, and disabling it is what waits for the second admin.
//
// Every step is in the activity log (approval.requested, approval.approved,
// approval.rejected, approval.cancelled) and, through it, in the alert
// events (activity.approval.*).

const (
	approvalPolicyDisable = "policy.disable"
	// approvalPolicyDelete is no longer asked for (migration 029 cancelled
	// the pending ones); decided requests of this kind stay in the history.
	approvalPolicyDelete   = "policy.delete"
	approvalContentStorage = "content_storage.enable"
	approvalOrgDelete      = "org.delete"

	defaultApprovalExpiryHours = 24
	maxApprovalExpiryHours     = 720
	maxApprovalNoteRunes       = 500
)

// approvalKinds names every kind a change can ask for.
var approvalKinds = []string{approvalPolicyDisable, approvalContentStorage, approvalOrgDelete}

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

type approvalActor struct {
	ID    *uuid.UUID `json:"id"`
	Email *string    `json:"email"`
}

// approvalRequest is one row as the API returns it.
type approvalRequest struct {
	ID     uuid.UUID `json:"id"`
	OrgID  uuid.UUID `json:"org_id"`
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

const approvalColumns = `a.id, a.org_id, a.kind, a.target, p.name, a.payload, a.reason, a.status, a.requested_by, a.requested_by_email,
	a.decided_by, a.decided_by_email, a.decided_at, a.decision_note, a.expires_at, a.created_at`

const approvalFrom = ` FROM approval_requests a
	LEFT JOIN policies p ON a.kind LIKE 'policy.%' AND p.org_id = a.org_id AND p.id::text = a.target`

func scanApproval(row pgx.Row) (approvalRequest, error) {
	var r approvalRequest
	var reqID, decID *uuid.UUID
	var reqEmail, decEmail *string
	err := row.Scan(&r.ID, &r.OrgID, &r.Kind, &r.Target, &r.TargetLabel, &r.Payload, &r.Reason, &r.Status, &reqID, &reqEmail,
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

func (r approvalRequest) target() string {
	if r.Target == nil {
		return ""
	}
	return *r.Target
}

// expireApprovals marks the org's pending requests past their time.
func expireApprovals(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx,
		`UPDATE approval_requests SET status = 'expired' WHERE org_id = $1 AND status = 'pending' AND expires_at <= NOW()`, org)
	return err
}

// cancelledApproval is a request cancelled because its target is gone or
// already in the requested state.
type cancelledApproval struct {
	ID     uuid.UUID
	Kind   string
	Target string
	Reason string
}

const (
	reasonPolicyGone     = "the policy no longer exists"
	reasonPolicyDisabled = "the policy is already disabled"
	reasonDeleteNoLonger = "deleting a policy no longer needs approval: disable it (which does), then delete it"
)

// cancelOrphanedApprovals cancels the org's pending requests to disable a
// policy that is gone or already disabled, and returns them for the log.
func cancelOrphanedApprovals(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]cancelledApproval, error) {
	var out []cancelledApproval
	for _, c := range []struct{ cond, reason string }{
		{`NOT EXISTS (SELECT 1 FROM policies p WHERE p.org_id = a.org_id AND p.id::text = a.target)`, reasonPolicyGone},
		{`EXISTS (SELECT 1 FROM policies p WHERE p.org_id = a.org_id AND p.id::text = a.target AND NOT p.enabled)`, reasonPolicyDisabled},
	} {
		rows, err := tx.Query(ctx,
			`UPDATE approval_requests a SET status = 'cancelled', decided_at = NOW(), decision_note = $2
			 WHERE a.org_id = $1 AND a.status = 'pending' AND a.kind = 'policy.disable' AND `+c.cond+`
			 RETURNING a.id, a.kind, COALESCE(a.target, '')`, org, c.reason)
		if err != nil {
			return nil, err
		}
		got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (cancelledApproval, error) {
			x := cancelledApproval{Reason: c.reason}
			return x, row.Scan(&x.ID, &x.Kind, &x.Target)
		})
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// logCancelled records cancelled requests in the org's activity log.
func logCancelled(c *fiber.Ctx, db *pgxpool.Pool, org uuid.UUID, list []cancelledApproval) {
	for _, x := range list {
		logActivity(c, db, &org, "approval.cancelled", x.Target, map[string]any{"approval_id": x.ID, "kind": x.Kind, "reason": x.Reason})
	}
}

// requestApproval records a pending request of the caller and answers 202
// with it. reason is the requester's; target a policy id or the org id. A
// request for the same change that is already pending is answered instead
// (already_pending true), and not logged again.
func requestApproval(c *fiber.Ctx, db *pgxpool.Pool, org uuid.UUID, kind, target string, payload map[string]any, reason string) error {
	raw, err := json.Marshal(payload)
	if err != nil || payload == nil {
		raw = []byte("{}")
	}
	reason = truncateRunes(strings.TrimSpace(reason), maxApprovalNoteRunes)
	var (
		out      approvalRequest
		existing bool
	)
	err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
		// An expired request no longer holds the one pending slot.
		if err := expireApprovals(c.Context(), tx, org); err != nil {
			return err
		}
		_, hours, err := twoPersonSettings(c.Context(), tx, org)
		if err != nil {
			return err
		}
		var id uuid.UUID
		err = tx.QueryRow(c.Context(),
			`INSERT INTO approval_requests (org_id, kind, target, payload, reason, requested_by, requested_by_email, expires_at)
			 VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), $6, (SELECT email FROM users WHERE id = $6),
			   NOW() + make_interval(hours => $7))
			 ON CONFLICT (org_id, kind, (COALESCE(target, ''))) WHERE status = 'pending' DO NOTHING
			 RETURNING id`,
			org, kind, target, raw, reason, nullUUID(auth.UserID(c)), hours).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			existing = true
			err = tx.QueryRow(c.Context(),
				`SELECT id FROM approval_requests WHERE org_id = $1 AND kind = $2 AND COALESCE(target, '') = $3 AND status = 'pending'`,
				org, kind, target).Scan(&id)
		}
		if err != nil {
			return err
		}
		out, err = scanApproval(tx.QueryRow(c.Context(), `SELECT `+approvalColumns+approvalFrom+` WHERE a.id = $1`, id))
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	if !existing {
		logActivity(c, db, &org, "approval.requested", target, map[string]any{
			"approval_id": out.ID, "kind": kind, "reason": reason, "expires_at": out.ExpiresAt})
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"approval_required": true, "already_pending": existing, "request": out})
}

// approvalStatuses are the values of ?status= besides all.
var approvalStatuses = []string{"pending", "approved", "rejected", "expired", "cancelled"}

// listApprovals answers GET /organizations/:orgId/approvals?status=pending
// (the default; all, approved, rejected, expired or cancelled), newest first.
func listApprovals(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		status := c.Query("status", "pending")
		if status != "all" && !slices.Contains(approvalStatuses, status) {
			return c.Status(400).JSON(fiber.Map{"error": "status must be pending, approved, rejected, expired, cancelled or all"})
		}
		items := []approvalRequest{}
		var cancelled []cancelledApproval
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := expireApprovals(c.Context(), tx, org); err != nil {
				return err
			}
			var err error
			if cancelled, err = cancelOrphanedApprovals(c.Context(), tx, org); err != nil {
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
		logCancelled(c, db, org, cancelled)
		return c.JSON(fiber.Map{"items": items})
	}
}

// listInstanceApprovals answers GET /admin/approvals (instance admin): the
// pending organization deletions of every organization, which an instance
// administrator may approve. Each item's payload names the organization.
func listInstanceApprovals(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		items := []approvalRequest{}
		err := withInstanceScope(c.Context(), db, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				// No policy names here: policies are read per org only.
				`SELECT `+approvalColumns+` FROM approval_requests a LEFT JOIN (SELECT NULL::text AS name) p ON false
				 WHERE a.kind = 'org.delete' AND a.status = 'pending' AND a.expires_at > NOW()
				 ORDER BY a.created_at DESC, a.id DESC LIMIT 200`)
			if err != nil {
				return err
			}
			items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (approvalRequest, error) { return scanApproval(row) })
			return err
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
	errOrgDeleteApprover  = errors.New("only another owner of the organization or an instance administrator can approve deleting it")
	errNotOrgAdmin        = errors.New("only an admin of the organization can decide this request")
)

// approvalVoid stops an approval whose change cannot apply any more (the
// policy is gone or already disabled): the request is cancelled instead.
type approvalVoid struct{ reason string }

func (e *approvalVoid) Error() string { return e.reason }

// callerStanding is the caller's role in the org ("" for none) and whether
// they are an active instance administrator. The routes let instance
// administrators through (orgRoleOrInstanceAdmin); the handlers decide.
func callerStanding(ctx context.Context, db *pgxpool.Pool, org, user uuid.UUID) (auth.Role, bool, error) {
	var instance bool
	err := db.QueryRow(ctx, `SELECT is_instance_admin AND disabled_at IS NULL FROM users WHERE id = $1`, user).Scan(&instance)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	var role string
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role::text FROM org_memberships WHERE user_id = $1 AND org_id = $2`, user, org).Scan(&role)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	return auth.Role(role), instance, nil
}

// mayDecide says whether the caller may approve (or reject) a request of
// kind. An organization's deletion is approved by another owner or an
// instance administrator; it is rejected by them, by an admin of the org or
// withdrawn by its requester. Every other kind is decided by an admin of the
// org.
func mayDecide(kind string, role auth.Role, instance, approve, requester bool) error {
	if kind == approvalOrgDelete {
		if role == auth.RoleOwner || instance {
			return nil
		}
		if approve {
			return errOrgDeleteApprover
		}
	}
	if auth.HasRole(role, auth.RoleAdmin) || (requester && !approve) {
		return nil
	}
	return errNotOrgAdmin
}

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

// applyApproval makes the approved change, as the approver. It changes only
// what the request is about: approving a disable flips enabled and keeps
// every other edit made to the policy since the request.
func applyApproval(ctx context.Context, tx pgx.Tx, org uuid.UUID, r approvalRequest, approver uuid.UUID) error {
	switch r.Kind {
	case approvalContentStorage:
		_, err := tx.Exec(ctx, `UPDATE organizations SET audit_store_content = true, updated_at = NOW() WHERE id = $1`, org)
		return err
	case approvalPolicyDisable:
		pID, err := uuid.Parse(r.target())
		if err != nil {
			return &approvalVoid{reasonPolicyGone}
		}
		var enabled bool
		err = tx.QueryRow(ctx, `SELECT enabled FROM policies WHERE id = $1 AND org_id = $2 FOR UPDATE`, pID, org).Scan(&enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return &approvalVoid{reasonPolicyGone}
		}
		if err != nil {
			return err
		}
		if !enabled {
			return &approvalVoid{reasonPolicyDisabled}
		}
		if _, err := tx.Exec(ctx,
			`UPDATE policies SET enabled = false, version = version + 1, updated_at = NOW() WHERE id = $1 AND org_id = $2`, pID, org); err != nil {
			return err
		}
		return recordPolicyVersion(ctx, tx, org, pID, approver, versionUpdate, "disabled by approved request "+r.ID.String(), nil)
	case approvalPolicyDelete:
		return &approvalVoid{reasonDeleteNoLonger}
	case approvalOrgDelete:
		if org == defaultOrgID {
			return &approvalVoid{"the default organization cannot be deleted"}
		}
		return deleteOrgRows(ctx, tx, org)
	}
	return fmt.Errorf("unknown approval kind %q", r.Kind)
}

// deleteOrgRows removes the organization and everything it owns. Audit rows
// do not cascade (migration 001), so they go first.
func deleteOrgRows(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, org); err != nil {
		return err
	}
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
	case approvalOrgDelete:
		return "org.deleted"
	}
	return "approval.applied"
}

// cancelRequest marks a request cancelled by decider with reason.
func cancelRequest(ctx context.Context, tx pgx.Tx, id, decider uuid.UUID, reason string) error {
	_, err := tx.Exec(ctx,
		`UPDATE approval_requests SET status = 'cancelled', decided_by = $2, decided_by_email = (SELECT email FROM users WHERE id = $2),
		   decided_at = NOW(), decision_note = $3 WHERE id = $1`, id, nullUUID(decider), reason)
	return err
}

// approveRequest answers POST .../approvals/:id/approve {note}: another
// admin than the requester applies the change. A request whose change no
// longer applies is cancelled instead: 409 approval_cancelled with it.
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
		role, instance, err := callerStanding(c.Context(), db, org, actor)
		if err != nil {
			return serverError(c, err)
		}
		var (
			r    approvalRequest
			void *approvalVoid
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if r, err = decideApproval(c.Context(), tx, org, id); err != nil {
				return err
			}
			if r.RequestedBy != nil && r.RequestedBy.ID != nil && *r.RequestedBy.ID == actor {
				return errSelfApproval
			}
			if err := mayDecide(r.Kind, role, instance, true, false); err != nil {
				return err
			}
			if err := applyApproval(c.Context(), tx, org, r, actor); err != nil {
				if errors.As(err, &void) {
					return cancelRequest(c.Context(), tx, id, actor, void.reason)
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
		if void != nil {
			logCancelled(c, db, org, []cancelledApproval{{ID: id, Kind: r.Kind, Target: r.target(), Reason: void.reason}})
			out, err := loadApproval(c.Context(), db, org, id)
			if err != nil {
				return serverError(c, err)
			}
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": void.reason + "; the request is cancelled", "code": "approval_cancelled", "request": out})
		}
		details := map[string]any{"approval_id": id, "kind": r.Kind, "note": note, "requested_by": r.RequestedBy}
		if r.Kind == approvalOrgDelete {
			// The org's log went with it: the instance log keeps the trace.
			details["org_id"] = org
			details["payload"] = r.Payload
			details["reason"] = r.Reason
			details["instance_admin"] = instance
			writeActivity(c.Context(), db, activityEntry{ActorID: actor, Action: "approval.approved", Target: org.String(), IP: clientIP(c),
				Details: details})
			writeActivity(c.Context(), db, activityEntry{ActorID: actor, Action: "org.deleted", Target: org.String(), IP: clientIP(c),
				Details: map[string]any{"approval_id": id, "payload": r.Payload, "reason": r.Reason, "requested_by": r.RequestedBy}})
			slog.Info("organization deleted", "org", org, "by", actor, "approval", id)
			return c.Status(204).Send(nil)
		}
		logActivity(c, db, &org, "approval.approved", r.target(), details)
		logActivity(c, db, &org, effectAction(r.Kind), r.target(), map[string]any{"approval_id": id, "kind": r.Kind})
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
		role, instance, err := callerStanding(c.Context(), db, org, actor)
		if err != nil {
			return serverError(c, err)
		}
		var r approvalRequest
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if r, err = decideApproval(c.Context(), tx, org, id); err != nil {
				return err
			}
			mine := r.RequestedBy != nil && r.RequestedBy.ID != nil && *r.RequestedBy.ID == actor
			if err := mayDecide(r.Kind, role, instance, false, mine); err != nil {
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
		logActivity(c, db, &org, "approval.rejected", r.target(), map[string]any{"approval_id": id, "kind": r.Kind, "note": note})
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
	case errors.Is(err, errSelfApproval), errors.Is(err, errOrgDeleteApprover), errors.Is(err, errNotOrgAdmin):
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
	case errors.Is(err, errOrgDeleteApprover):
		return "owner_or_instance_admin_required"
	case errors.Is(err, errNotOrgAdmin):
		return "forbidden"
	}
	return ""
}

// deleteOrg answers DELETE /organizations/:orgId {confirm: <slug>, reason}.
// Deleting an organization always takes two people, whatever its
// two-person setting: an owner's call records a request (202) that another
// owner or an instance administrator approves. An instance administrator
// may delete it at once but must give a reason, which the instance's
// activity log keeps. The default organization (the instance's first,
// migration 002) is never deleted.
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
		req.Reason = strings.TrimSpace(req.Reason)
		if len([]rune(req.Reason)) > maxApprovalNoteRunes {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("reason must be at most %d characters", maxApprovalNoteRunes)})
		}
		if org == defaultOrgID {
			return auth.Deny(c, fiber.StatusConflict, "default_org", "the default organization cannot be deleted")
		}
		var slug, name string
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(), `SELECT slug, name FROM organizations WHERE id = $1`, org).Scan(&slug, &name)
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
		actor := auth.UserID(c)
		role, instance, err := callerStanding(c.Context(), db, org, actor)
		if err != nil {
			return serverError(c, err)
		}
		if !instance {
			if role != auth.RoleOwner {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
			}
			return requestApproval(c, db, org, approvalOrgDelete, org.String(), map[string]any{"slug": slug, "name": name}, req.Reason)
		}
		if req.Reason == "" {
			return auth.Deny(c, fiber.StatusBadRequest, "reason_required",
				"an instance administrator deleting an organization directly must give a reason")
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return deleteOrgRows(c.Context(), tx, org)
		})
		if errors.Is(err, errApprovalTargetGone) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		writeActivity(c.Context(), db, activityEntry{ActorID: actor, Action: "org.deleted", Target: org.String(), IP: clientIP(c),
			Details: map[string]any{"slug": slug, "name": name, "reason": req.Reason, "instance_admin": true}})
		slog.Info("organization deleted by an instance administrator", "org", org, "slug", slug, "by", actor)
		return c.Status(204).Send(nil)
	}
}

// orgRoleOrInstanceAdmin is auth.RequireRole(min), except that an active
// instance administrator passes for any organization, a member or not (the
// org's login rules are not applied to them, as on /admin). The handlers
// behind it decide what an instance administrator may do (callerStanding).
func orgRoleOrInstanceAdmin(db *pgxpool.Pool, min auth.Role) fiber.Handler {
	member := auth.RequireRole(db, min)
	return func(c *fiber.Ctx) error {
		var instance bool
		err := db.QueryRow(c.Context(), `SELECT is_instance_admin AND disabled_at IS NULL FROM users WHERE id = $1`, auth.UserID(c)).
			Scan(&instance)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return serverError(c, err)
		}
		if !instance {
			return member(c)
		}
		org, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		c.Locals("org_id", org)
		return c.Next()
	}
}
