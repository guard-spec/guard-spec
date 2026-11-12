//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// inputRow reads the org's stored input settings: mode, max tokens (-1 for
// NULL), file types, unreadable action; ok false with no row.
func (h *approvalHarness) inputRow(org uuid.UUID) (mode string, max int, types []string, action string, ok bool) {
	h.t.Helper()
	var n *int
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx,
			`SELECT input_mode, max_input_tokens, allowed_file_types, unreadable_file_action FROM org_input_settings WHERE org_id = $1`, org).
			Scan(&mode, &n, &types, &action)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, nil, "", false
	}
	if err != nil {
		h.t.Fatal(err)
	}
	max = -1
	if n != nil {
		max = *n
	}
	return mode, max, types, action, true
}

// activityCount counts the org's activity rows of action.
func (h *approvalHarness) activityCount(org uuid.UUID, action string) int {
	h.t.Helper()
	var n int
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT count(*) FROM activity_log WHERE org_id = $1 AND action = $2`, org, action).Scan(&n)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

// An org without settings inherits the instance; the ceiling comes from the
// gateway's /readyz, or is the short path's limit when it cannot be read.
func TestInputSettingsInheritAndCeiling(t *testing.T) {
	h := newApprovalHarness(t)
	admin, viewer := h.user(false), h.user(false)
	org := h.org(false, map[uuid.UUID]string{admin: "admin", viewer: "viewer"})

	code, out := h.do(org, viewer, "GET", "/input-settings", "")
	inst, _ := out["instance"].(map[string]any)
	if code != 200 || out["inherit"] != true || out["settings"] != nil || inst["source"] != "default" ||
		inst["max_input_tokens_ceiling"] != float64(40000) || out["pending"] != nil {
		t.Fatalf("inherit: %d %v", code, out)
	}
	if code, out = h.do(org, admin, "PUT", "/input-settings", `{"input_mode":"hybrid","max_input_tokens":40001}`); code != 400 ||
		!strings.Contains(out["error"].(string), "at most 40000") {
		t.Fatalf("over the default ceiling: %d %v", code, out)
	}

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ready","version":"0.7.0","detector":{},"input":{"max_scan_tokens":200000,` +
			`"max_input_tokens_ceiling":200000,"pdf_extract":true,"unscanned_parts":"log","readable_file_types":["pdf"]}}`))
	}))
	defer gw.Close()
	h.gw.gatewayURL = gw.URL
	code, out = h.do(org, admin, "PUT", "/input-settings", `{"input_mode":"hybrid","max_input_tokens":150000,"allowed_file_types":["PDF","pdf"]}`)
	inst, _ = out["instance"].(map[string]any)
	if code != 200 || out["inherit"] != false || inst["source"] != "gateway" || inst["max_input_tokens_ceiling"] != float64(200000) ||
		inst["pdf_extract"] != true || inst["unscanned_parts"] != "log" {
		t.Fatalf("within the gateway's ceiling: %d %v", code, out)
	}
	if mode, max, types, action, ok := h.inputRow(org); !ok || mode != "hybrid" || max != 150000 ||
		strings.Join(types, ",") != "pdf" || action != "block" {
		t.Errorf("stored: %s %d %v %s %v", mode, max, types, action, ok)
	}
	if code, out = h.do(org, admin, "PUT", "/input-settings", `{"input_mode":"hybrid","max_input_tokens":200001}`); code != 400 {
		t.Errorf("over the gateway's ceiling: %d %v", code, out)
	}
	for _, body := range []string{
		`{"input_mode":"image_only"}`, `{}`, `{"input_mode":"hybrid","allowed_file_types":["docx"]}`,
		`{"input_mode":"hybrid","unreadable_file_action":"ignore"}`, `{"input_mode":"hybrid","max_input_tokens":0}`,
		`{"input_mode":"hybrid","typo":1}`,
	} {
		if code, out = h.do(org, admin, "PUT", "/input-settings", body); code != 400 {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	// Without two-person approval, loosening applies at once and is logged.
	before := h.activityCount(org, "input_settings.updated")
	if code, out = h.do(org, admin, "PUT", "/input-settings",
		`{"input_mode":"hybrid","allowed_file_types":["pdf"],"unreadable_file_action":"pass"}`); code != 200 {
		t.Fatalf("loosen: %d %v", code, out)
	}
	if _, max, _, action, _ := h.inputRow(org); max != -1 || action != "pass" {
		t.Errorf("loosened: max %d action %s", max, action)
	}
	if h.activityCount(org, "input_settings.updated") != before+1 {
		t.Error("loosening not in the activity log")
	}
	var loosened string
	_ = tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT details->>'loosened' FROM activity_log WHERE org_id = $1 AND action = 'input_settings.updated'
			ORDER BY seq DESC LIMIT 1`, org).Scan(&loosened)
	})
	if loosened != `["max_input_tokens", "unreadable_file_action"]` {
		t.Errorf("logged loosened = %s", loosened)
	}
	// Back to the instance's behaviour.
	if code, out = h.do(org, admin, "DELETE", "/input-settings", ""); code != 200 || out["inherit"] != true {
		t.Fatalf("reset: %d %v", code, out)
	}
	if _, _, _, _, ok := h.inputRow(org); ok {
		t.Error("row left after reset")
	}
}

// With two-person approval on, tightening applies at once and loosening
// waits for another admin; the tightening part of a mixed change applies.
func TestInputSettingsTwoPerson(t *testing.T) {
	h := newApprovalHarness(t)
	a, b := h.user(false), h.user(false)
	org := h.org(true, map[uuid.UUID]string{a: "admin", b: "admin"})

	// From the instance's behaviour every setting is a tightening.
	if code, out := h.do(org, a, "PUT", "/input-settings", `{"input_mode":"hybrid","allowed_file_types":["pdf"],"max_input_tokens":8000}`); code != 200 {
		t.Fatalf("first settings: %d %v", code, out)
	}
	// Mixed: max tokens lowered (now) and unreadable files passed (waits).
	code, out := h.do(org, a, "PUT", "/input-settings",
		`{"input_mode":"hybrid","allowed_file_types":["pdf"],"max_input_tokens":4000,"unreadable_file_action":"pass","reason":"scanned contracts"}`)
	if code != 202 || out["approval_required"] != true || out["already_pending"] != false || out["applied_now"] != true {
		t.Fatalf("mixed: %d %v", code, out)
	}
	reqID := requestID(t, out)
	if _, max, _, action, _ := h.inputRow(org); max != 4000 || action != "block" {
		t.Errorf("after the request: max %d action %s; want 4000 block", max, action)
	}
	state, _ := out["state"].(map[string]any)
	if p, _ := state["pending"].(map[string]any); p == nil || p["id"] != reqID || p["kind"] != approvalInputLoosen {
		t.Errorf("state pending = %v", state["pending"])
	}
	// The same change again answers with it.
	code, out = h.do(org, b, "PUT", "/input-settings",
		`{"input_mode":"hybrid","allowed_file_types":["pdf"],"max_input_tokens":4000,"unreadable_file_action":"pass"}`)
	if code != 202 || out["already_pending"] != true || requestID(t, out) != reqID {
		t.Fatalf("again: %d %v", code, out)
	}
	// A different loosening meanwhile is refused.
	code, out = h.do(org, b, "PUT", "/input-settings", `{"input_mode":"hybrid","allowed_file_types":["pdf"],"max_input_tokens":9000}`)
	if code != 409 || out["code"] != "approval_pending" {
		t.Fatalf("other loosening: %d %v", code, out)
	}
	if code, out = h.do(org, a, "POST", "/approvals/"+reqID+"/approve", ""); code != 403 || out["code"] != "self_approval" {
		t.Errorf("self approval: %d %v", code, out)
	}
	if code, out = h.do(org, b, "POST", "/approvals/"+reqID+"/approve", `{"note":"ok"}`); code != 200 || out["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if _, max, _, action, _ := h.inputRow(org); max != 4000 || action != "pass" {
		t.Errorf("after approval: max %d action %s", max, action)
	}
	if h.activityCount(org, "approval.approved") != 1 || h.activityCount(org, "input_settings.updated") < 3 {
		t.Error("approval or its effect missing from the activity log")
	}

	// A tightening while a loosening waits applies and cancels it.
	code, out = h.do(org, a, "PUT", "/input-settings", `{"input_mode":"hybrid","allowed_file_types":["pdf"],"unreadable_file_action":"pass"}`)
	if code != 202 {
		t.Fatalf("raise max: %d %v", code, out)
	}
	raise := requestID(t, out)
	if code, out = h.do(org, b, "PUT", "/input-settings", `{"input_mode":"text_only","max_input_tokens":4000}`); code != 200 {
		t.Fatalf("tighten: %d %v", code, out)
	}
	if st, note := h.status(org, raise); st != "cancelled" || note != reasonInputChanged {
		t.Errorf("pending after tightening: %s %q", st, note)
	}
	if mode, _, types, action, _ := h.inputRow(org); mode != "text_only" || len(types) != 0 || action != "block" {
		t.Errorf("tightened: %s %v %s", mode, types, action)
	}

	// An approval of settings that moved since is cancelled.
	code, out = h.do(org, a, "DELETE", "/input-settings", `{"reason":"back to defaults"}`)
	if code != 202 || out["applied_now"] != false {
		t.Fatalf("reset request: %d %v", code, out)
	}
	reset := requestID(t, out)
	h.exec(org, `UPDATE org_input_settings SET max_input_tokens = 100 WHERE org_id = $1`, org)
	if code, out = h.do(org, b, "POST", "/approvals/"+reset+"/approve", ""); code != 409 || out["code"] != "approval_cancelled" {
		t.Fatalf("stale approve: %d %v", code, out)
	}
	if _, max, _, _, ok := h.inputRow(org); !ok || max != 100 {
		t.Errorf("stale approval changed the settings: %d %v", max, ok)
	}
	// The list cancels a stale request too.
	code, out = h.do(org, a, "DELETE", "/input-settings", "")
	reset = requestID(t, out)
	h.exec(org, `UPDATE org_input_settings SET max_input_tokens = 50 WHERE org_id = $1`, org)
	if code, out = h.do(org, a, "GET", "/approvals", ""); code != 200 || len(out["items"].([]any)) != 0 {
		t.Errorf("list after a stale reset: %d %v", code, out)
	}
	if st, _ := h.status(org, reset); st != "cancelled" {
		t.Errorf("stale reset: %s", st)
	}
	// Approved, the reset brings back the instance's behaviour.
	code, out = h.do(org, a, "DELETE", "/input-settings", "")
	reset = requestID(t, out)
	if code, out = h.do(org, b, "POST", "/approvals/"+reset+"/approve", ""); code != 200 {
		t.Fatalf("approve reset: %d %v", code, out)
	}
	if _, _, _, _, ok := h.inputRow(org); ok {
		t.Error("settings left after the approved reset")
	}
}

func TestMigration030(t *testing.T) {
	up, err := os.ReadFile("../../migrations/030_org_input_settings.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/030_org_input_settings.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, envOr("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	org := uuid.New()
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'm', $2)`, org, org.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO org_input_settings (org_id, input_mode, allowed_file_types) VALUES ($1, 'hybrid', '{pdf}')`, org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO approval_requests (org_id, kind, target, expires_at)
			VALUES ($1, 'input_settings.loosen', 'input_settings', NOW() + interval '1 hour')`, org); err != nil {
			return err
		}
		// The checks refuse what the gateway could not apply.
		for i, bad := range []string{
			`UPDATE org_input_settings SET allowed_file_types = '{docx}' WHERE org_id = $1`,
			`UPDATE org_input_settings SET input_mode = 'text_only' WHERE org_id = $1`, // files listed in text_only
			`UPDATE org_input_settings SET unreadable_file_action = 'skip' WHERE org_id = $1`,
			`UPDATE org_input_settings SET max_input_tokens = 0 WHERE org_id = $1`,
		} {
			if _, err := tx.Exec(ctx, `SAVEPOINT bad`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, bad, org); err == nil {
				t.Errorf("check %d accepted %s", i, bad)
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT bad`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, string(down)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE org_id = $1`, org).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("input requests after down: %d", n)
		}
		var table *string
		if err := tx.QueryRow(ctx, `SELECT to_regclass('org_input_settings')::text`).Scan(&table); err != nil {
			return err
		}
		if table != nil {
			t.Error("org_input_settings left after down")
		}
		if _, err := tx.Exec(ctx, string(up)); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
}
