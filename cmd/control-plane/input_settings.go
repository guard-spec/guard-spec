// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Per-organization input settings (RF-113cd269, org_input_settings,
// migration 030; the rules are in internal/indirect/input.go).
//
//	GET    /organizations/:orgId/input-settings  the settings, the instance's limits, a pending loosening
//	PUT    /organizations/:orgId/input-settings  set them {input_mode, max_input_tokens, allowed_file_types, unreadable_file_action, reason}
//	DELETE /organizations/:orgId/input-settings  back to the instance's behaviour {reason}
//
// They live in their own table rather than in org_security: the gateway
// reads them on every request with the org's guard settings (one query, the
// same path), and org_security holds the login rules the gateway never
// reads. An org without a row inherits the instance's behaviour.
//
// The instance's limits come from the gateway's /readyz (GATEWAY_URL): its
// MAX_SCAN_TOKENS bounds max_input_tokens. When the gateway cannot be read
// the bound is indirect.ShortPathTokens; the gateway applies the smaller of
// the org's value and its own limit anyway.
//
// Tightening applies at once. Loosening (a file type added, max_input_tokens
// raised or removed, unreadable files passed, text_only to hybrid, back to
// the instance's behaviour) is always in the activity log; with two-person
// approval on it waits for a second admin: the tightening part of the same
// change applies at once, the rest becomes an input_settings.loosen request
// (payload {from, to, loosened}). One such request is pending at a time; a
// different loosening meanwhile is refused (409 approval_pending), and any
// change of the settings cancels the pending request, whose from no longer
// holds. Approving applies to only while the settings are still from.

const inputSettingsTarget = "input_settings"

// instanceInput is the instance's input limits as the API returns them.
type instanceInput struct {
	// Source is gateway (read from its /readyz) or default (the gateway
	// could not be read: the short path's limit is assumed).
	Source                string   `json:"source"`
	MaxInputTokensCeiling int      `json:"max_input_tokens_ceiling"`
	MaxScanTokens         *int     `json:"max_scan_tokens"`
	PDFExtract            *bool    `json:"pdf_extract"`
	UnscannedParts        *string  `json:"unscanned_parts"`
	ReadableFileTypes     []string `json:"readable_file_types"`
	Error                 *string  `json:"error,omitempty"`
}

// instanceInputLimits reads the gateway's input limits.
func instanceInputLimits(ctx context.Context, settings *appSettings, client *http.Client) instanceInput {
	out := instanceInput{Source: "default", MaxInputTokensCeiling: indirect.ShortPathTokens,
		ReadableFileTypes: indirect.ReadableFileTypes}
	fail := func(msg string) instanceInput {
		out.Error = &msg
		return out
	}
	if settings == nil || settings.gatewayURL == "" {
		return fail("GATEWAY_URL is not set: the control plane cannot read the gateway's limits")
	}
	st, err := fetchReadyz(ctx, client, settings.gatewayURL)
	if err != nil {
		return fail(err.Error())
	}
	if st.Input == nil {
		return fail("the gateway does not report its input limits (a version before 0.7.0?)")
	}
	in := st.Input
	out.Source = "gateway"
	out.MaxInputTokensCeiling = indirect.InputTokenCeiling(in.MaxScanTokens)
	if in.MaxScanTokens > 0 {
		out.MaxScanTokens = &in.MaxScanTokens
	}
	out.PDFExtract, out.UnscannedParts = &in.PDFExtract, &in.UnscannedParts
	if len(in.ReadableFileTypes) > 0 {
		out.ReadableFileTypes = in.ReadableFileTypes
	}
	return out
}

// inputSettingsState is the GET answer, and the 200 of a change.
type inputSettingsState struct {
	// Inherit: no settings, the instance's behaviour applies.
	Inherit           bool                    `json:"inherit"`
	Settings          *indirect.InputSettings `json:"settings"`
	UpdatedAt         *time.Time              `json:"updated_at"`
	Instance          instanceInput           `json:"instance"`
	TwoPersonApproval bool                    `json:"two_person_approval"`
	// Pending is the loosening waiting for a second admin, if any.
	Pending *approvalRequest `json:"pending"`
}

// inputChange is the payload of an input_settings.loosen request.
type inputChange struct {
	From     *indirect.InputSettings `json:"from"`
	To       *indirect.InputSettings `json:"to"`
	Loosened []string                `json:"loosened"`
}

// lockInputSettings serializes the changes of one org's input settings
// (there may be no row to lock), until tx ends.
func lockInputSettings(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('org_input_settings:' || $1::text, 0))`, org)
	return err
}

// loadInputSettings reads the org's settings in tx; nil: none.
func loadInputSettings(ctx context.Context, tx pgx.Tx, org uuid.UUID) (*indirect.InputSettings, *time.Time, error) {
	var s indirect.InputSettings
	var at time.Time
	err := tx.QueryRow(ctx,
		`SELECT input_mode, max_input_tokens, allowed_file_types, unreadable_file_action, updated_at
		 FROM org_input_settings WHERE org_id = $1`, org).
		Scan(&s.InputMode, &s.MaxInputTokens, &s.AllowedFileTypes, &s.UnreadableFileAction, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if s.AllowedFileTypes == nil {
		s.AllowedFileTypes = []string{}
	}
	return &s, &at, nil
}

// writeInputSettings stores s, or removes the row for nil.
func writeInputSettings(ctx context.Context, tx pgx.Tx, org uuid.UUID, s *indirect.InputSettings, by uuid.UUID) error {
	if s == nil {
		_, err := tx.Exec(ctx, `DELETE FROM org_input_settings WHERE org_id = $1`, org)
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO org_input_settings (org_id, input_mode, max_input_tokens, allowed_file_types, unreadable_file_action, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (org_id) DO UPDATE SET input_mode = EXCLUDED.input_mode, max_input_tokens = EXCLUDED.max_input_tokens,
		   allowed_file_types = EXCLUDED.allowed_file_types, unreadable_file_action = EXCLUDED.unreadable_file_action,
		   updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		org, s.InputMode, s.MaxInputTokens, s.AllowedFileTypes, s.UnreadableFileAction, nullUUID(by))
	return err
}

// pendingInputRequest loads the org's pending loosening for update; nil:
// none.
func pendingInputRequest(ctx context.Context, tx pgx.Tx, org uuid.UUID) (*approvalRequest, *inputChange, error) {
	r, err := scanApproval(tx.QueryRow(ctx,
		`SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id = $1 AND a.kind = $2 AND a.status = 'pending' FOR UPDATE OF a`,
		org, approvalInputLoosen))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var ch inputChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return &r, nil, nil // unreadable: treated as stale
	}
	return &r, &ch, nil
}

const reasonInputChanged = "the input settings changed after the request"

// cancelStaleInputRequest cancels the org's pending loosening when the
// settings are no longer what it was asked from.
func cancelStaleInputRequest(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]cancelledApproval, error) {
	r, ch, err := pendingInputRequest(ctx, tx, org)
	if err != nil || r == nil {
		return nil, err
	}
	cur, _, err := loadInputSettings(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	if ch != nil && cur.Equal(ch.From) {
		return nil, nil
	}
	if err := cancelRequest(ctx, tx, r.ID, uuid.Nil, reasonInputChanged); err != nil {
		return nil, err
	}
	return []cancelledApproval{{ID: r.ID, Kind: r.Kind, Target: r.target(), Reason: reasonInputChanged}}, nil
}

// applyInputLoosen applies an approved loosening, as the approver, while the
// settings are still those it was asked from.
func applyInputLoosen(ctx context.Context, tx pgx.Tx, org uuid.UUID, r approvalRequest, approver uuid.UUID) error {
	if err := lockInputSettings(ctx, tx, org); err != nil {
		return err
	}
	var ch inputChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return &approvalVoid{"the request does not say which settings to apply"}
	}
	cur, _, err := loadInputSettings(ctx, tx, org)
	if err != nil {
		return err
	}
	if !cur.Equal(ch.From) {
		return &approvalVoid{reasonInputChanged}
	}
	return writeInputSettings(ctx, tx, org, ch.To, approver)
}

// loadInputState builds the GET answer.
func loadInputState(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, inst instanceInput) (inputSettingsState, error) {
	out := inputSettingsState{Instance: inst}
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		var err error
		if out.Settings, out.UpdatedAt, err = loadInputSettings(ctx, tx, org); err != nil {
			return err
		}
		if out.TwoPersonApproval, _, err = twoPersonSettings(ctx, tx, org); err != nil {
			return err
		}
		r, err := scanApproval(tx.QueryRow(ctx,
			`SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id = $1 AND a.kind = $2 AND a.status = 'pending' AND a.expires_at > NOW()`,
			org, approvalInputLoosen))
		if err == nil {
			out.Pending = &r
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return nil
	})
	out.Inherit = out.Settings == nil
	return out, err
}

func getInputSettings(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	client := gatewayStatusClient(settings)
	return func(c *fiber.Ctx) error {
		out, err := loadInputState(c.Context(), db, orgID(c), instanceInputLimits(c.Context(), settings, client))
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}

// putInputSettings answers PUT .../input-settings.
func putInputSettings(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	client := gatewayStatusClient(settings)
	return func(c *fiber.Ctx) error {
		var req struct {
			indirect.InputSettings
			Reason string `json:"reason"`
		}
		dec := json.NewDecoder(bytes.NewReader(c.Body()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body: " + err.Error()})
		}
		inst := instanceInputLimits(c.Context(), settings, client)
		to := req.InputSettings
		if err := to.Normalize(inst.MaxInputTokensCeiling); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error(), "code": "invalid_input_settings"})
		}
		return changeInputSettings(c, db, inst, &to, req.Reason)
	}
}

// deleteInputSettings answers DELETE .../input-settings {reason}: back to
// the instance's behaviour, which loosens whatever the org had set.
func deleteInputSettings(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	client := gatewayStatusClient(settings)
	return func(c *fiber.Ctx) error {
		var req struct {
			Reason string `json:"reason"`
		}
		if len(bytes.TrimSpace(c.Body())) > 0 {
			if err := json.Unmarshal(c.Body(), &req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}
		return changeInputSettings(c, db, instanceInputLimits(c.Context(), settings, client), nil, req.Reason)
	}
}

// errInputPending refuses a loosening while a different one waits.
var errInputPending = errors.New("another change of the input settings is waiting for approval: approve, reject or withdraw it first")

// changeInputSettings moves the org's settings to to (nil: inherit), under
// the rules at the top of this file.
func changeInputSettings(c *fiber.Ctx, db *pgxpool.Pool, inst instanceInput, to *indirect.InputSettings, reason string) error {
	org, actor := orgID(c), auth.UserID(c)
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) > maxApprovalNoteRunes {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("reason must be at most %d characters", maxApprovalNoteRunes)})
	}
	var (
		from, written *indirect.InputSettings
		changed       bool
		loosened      []string
		request       *approvalRequest
		existing      bool
		pending       *approvalRequest
		cancelled     []cancelledApproval
	)
	err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
		ctx := c.Context()
		if err := lockInputSettings(ctx, tx, org); err != nil {
			return err
		}
		if err := expireApprovals(ctx, tx, org); err != nil {
			return err
		}
		var err error
		if from, _, err = loadInputSettings(ctx, tx, org); err != nil {
			return err
		}
		pr, pch, err := pendingInputRequest(ctx, tx, org)
		if err != nil {
			return err
		}
		twoPerson, _, err := twoPersonSettings(ctx, tx, org)
		if err != nil {
			return err
		}
		loosened = indirect.Loosened(from, to)
		written = to
		if len(loosened) > 0 && twoPerson {
			if pr != nil {
				if pch != nil && pch.From.Equal(from) && pch.To.Equal(to) {
					request, existing = pr, true // asked again
					written = from
					return nil
				}
				if pch != nil && pch.From.Equal(from) {
					pending = pr
					return errInputPending
				}
				// Stale: the settings moved since; it gives way to this one.
				if err := cancelRequest(ctx, tx, pr.ID, actor, reasonInputChanged); err != nil {
					return err
				}
				cancelled = append(cancelled, cancelledApproval{ID: pr.ID, Kind: pr.Kind, Target: pr.target(), Reason: reasonInputChanged})
			}
			written = indirect.Tightened(from, to)
			if !written.Equal(from) {
				if err := writeInputSettings(ctx, tx, org, written, actor); err != nil {
					return err
				}
				changed = true
			}
			payload, err := json.Marshal(inputChange{From: written, To: to, Loosened: loosened})
			if err != nil {
				return err
			}
			r, dup, err := insertApproval(ctx, tx, org, approvalInputLoosen, inputSettingsTarget, payload, reason, actor)
			if err != nil {
				return err
			}
			request, existing = &r, dup
			return nil
		}
		if !to.Equal(from) {
			if err := writeInputSettings(ctx, tx, org, to, actor); err != nil {
				return err
			}
			changed = true
		}
		// A pending loosening asked from the old settings no longer applies.
		if pr != nil && (pch == nil || !pch.From.Equal(to)) {
			if err := cancelRequest(ctx, tx, pr.ID, actor, reasonInputChanged); err != nil {
				return err
			}
			cancelled = append(cancelled, cancelledApproval{ID: pr.ID, Kind: pr.Kind, Target: pr.target(), Reason: reasonInputChanged})
		}
		return nil
	})
	if errors.Is(err, errInputPending) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error(), "code": "approval_pending", "request": pending})
	}
	if err != nil {
		return serverError(c, err)
	}
	logCancelled(c, db, org, cancelled)
	if changed {
		slog.Info("org input settings changed", "org", org, "by", actor)
		logActivity(c, db, &org, "input_settings.updated", inputSettingsTarget, map[string]any{
			"from": from, "to": written, "loosened": indirect.Loosened(from, written), "reason": reason})
	}
	if request != nil {
		if !existing {
			logActivity(c, db, &org, "approval.requested", inputSettingsTarget, map[string]any{
				"approval_id": request.ID, "kind": approvalInputLoosen, "reason": reason, "expires_at": request.ExpiresAt,
				"from": written, "to": to, "loosened": loosened})
		}
		state, err := loadInputState(c.Context(), db, org, inst)
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"approval_required": true, "already_pending": existing,
			"request": request, "applied_now": changed, "state": state})
	}
	state, err := loadInputState(c.Context(), db, org, inst)
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(state)
}
