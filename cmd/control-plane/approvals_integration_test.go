//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// With two_person_approval on, disabling or deleting a policy, turning
// content storage on and deleting the org become pending requests; the
// requester cannot approve, another admin can, a rejection changes nothing,
// and a request past its time expires. Off, the same calls apply at once.
func TestTwoPersonApproval(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, envOr("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}

	org, requester, approver := uuid.New(), uuid.New(), uuid.New()
	for _, u := range []struct {
		id    uuid.UUID
		email string
	}{{requester, "req-" + org.String() + "@example.com"}, {approver, "app-" + org.String() + "@example.com"}} {
		if _, err := db.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2)`, u.id, u.email); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{requester, approver}) })
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'two',$2)`, org, org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO org_security (org_id, two_person_approval, approval_expiry_hours) VALUES ($1, true, 2)`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		})
	})

	app := fiber.New()
	setOrg := func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.SendStatus(400)
		}
		c.Locals("org_id", id)
		if u, err := uuid.Parse(c.Get("X-User")); err == nil {
			c.Locals("user_id", u)
		}
		return c.Next()
	}
	app.Patch("/o/:orgId", setOrg, updateOrgSettings(db))
	app.Delete("/o/:orgId", setOrg, deleteOrg(db))
	app.Post("/o/:orgId/policies", setOrg, createPolicy(db, eng))
	app.Put("/o/:orgId/policies/:id", setOrg, updatePolicy(db, eng))
	app.Delete("/o/:orgId/policies/:id", setOrg, deletePolicy(db))
	app.Get("/o/:orgId/approvals", setOrg, listApprovals(db))
	app.Post("/o/:orgId/approvals/:id/approve", setOrg, approveRequest(db))
	app.Post("/o/:orgId/approvals/:id/reject", setOrg, rejectRequest(db))

	do := func(user uuid.UUID, method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, "/o/"+org.String()+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User", user.String())
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"_raw": string(raw)}
		}
		return resp.StatusCode, out
	}
	requestID := func(out map[string]any) string {
		t.Helper()
		r, _ := out["request"].(map[string]any)
		id, _ := r["id"].(string)
		if id == "" {
			t.Fatalf("no request in %v", out)
		}
		return id
	}
	policyEnabled := func(id string) (enabled, exists bool) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT enabled FROM policies WHERE id = $1`, id).Scan(&enabled)
		})
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			t.Fatal(err)
		}
		return enabled, err == nil
	}

	rule := `{"name":"a","action":"block","condition":{"field":"scores.l2","operator":">","value":0.9}}`
	code, out := do(requester, "POST", "/policies", `{"name":"guarded","rules":[`+rule+`]}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	pID := out["id"].(string)

	// Disabling waits; the rest of the save applies.
	code, out = do(requester, "PUT", "/policies/"+pID, `{"enabled":false,"description":"d","reason":"too many blocks"}`)
	if code != 202 || out["approval_required"] != true {
		t.Fatalf("disable: %d %v", code, out)
	}
	disableReq := requestID(out)
	if enabled, _ := policyEnabled(pID); !enabled {
		t.Fatal("policy disabled before approval")
	}
	code, out = do(requester, "GET", "/approvals", "")
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("pending: %d %v", code, out)
	}
	first := items[0].(map[string]any)
	if first["kind"] != approvalPolicyDisable || first["target_label"] != "guarded" || first["reason"] != "too many blocks" || first["status"] != "pending" {
		t.Errorf("pending item = %v", first)
	}
	if code, out = do(requester, "POST", "/approvals/"+disableReq+"/approve", ""); code != 403 || out["code"] != "self_approval" {
		t.Errorf("self approval: %d %v", code, out)
	}
	if code, out = do(approver, "POST", "/approvals/"+disableReq+"/approve", `{"note":"agreed"}`); code != 200 || out["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if enabled, _ := policyEnabled(pID); enabled {
		t.Error("policy still enabled after approval")
	}
	if code, out = do(approver, "POST", "/approvals/"+disableReq+"/approve", ""); code != 409 || out["code"] != "approval_not_pending" {
		t.Errorf("second approval: %d %v", code, out)
	}

	// A rejected delete changes nothing.
	code, out = do(requester, "DELETE", "/policies/"+pID+"?reason=unused", "")
	if code != 202 {
		t.Fatalf("delete: %d %v", code, out)
	}
	deleteReq := requestID(out)
	if code, out = do(approver, "POST", "/approvals/"+deleteReq+"/reject", `{"note":"keep it"}`); code != 200 || out["status"] != "rejected" || out["decision_note"] != "keep it" {
		t.Fatalf("reject: %d %v", code, out)
	}
	if _, exists := policyEnabled(pID); !exists {
		t.Error("policy deleted despite the rejection")
	}

	// Content storage: the request expires before anyone decides.
	code, out = do(requester, "PATCH", "", `{"audit_store_content":true}`)
	if code != 202 {
		t.Fatalf("content storage: %d %v", code, out)
	}
	contentReq := requestID(out)
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE approval_requests SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, contentReq)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, out = do(approver, "POST", "/approvals/"+contentReq+"/approve", ""); code != 409 || out["code"] != "approval_expired" {
		t.Errorf("expired approval: %d %v", code, out)
	}
	code, out = do(approver, "GET", "/approvals?status=expired", "")
	if code != 200 || len(out["items"].([]any)) != 1 {
		t.Errorf("expired list: %d %v", code, out)
	}
	var stores bool
	_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT audit_store_content FROM organizations WHERE id = $1`, org).Scan(&stores)
	})
	if stores {
		t.Error("content storage turned on without approval")
	}
	// Turning it off never needs approval.
	if code, _ = do(requester, "PATCH", "", `{"audit_store_content":false}`); code != 200 {
		t.Errorf("storage off: %d", code)
	}

	// Off: the same call applies at once.
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE org_security SET two_person_approval = false WHERE org_id = $1`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, out = do(requester, "PATCH", "", `{"audit_store_content":true}`); code != 200 || out["audit_store_content"] != true {
		t.Errorf("storage on without two-person: %d %v", code, out)
	}
	if code, _ = do(requester, "DELETE", "/policies/"+pID, ""); code != 204 {
		t.Errorf("delete without two-person: %d", code)
	}

	// Deleting the org: the slug confirms it; with two-person on it waits.
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE org_security SET two_person_approval = true WHERE org_id = $1`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, out = do(requester, "DELETE", "", `{"confirm":"wrong"}`); code != 400 || out["code"] != "confirm_mismatch" {
		t.Errorf("wrong confirm: %d %v", code, out)
	}
	code, out = do(requester, "DELETE", "", `{"confirm":"`+org.String()+`"}`)
	if code != 202 {
		t.Fatalf("org delete: %d %v", code, out)
	}
	orgReq := requestID(out)
	if code, out = do(approver, "POST", "/approvals/"+orgReq+"/approve", ""); code != 204 {
		t.Fatalf("approve org delete: %d %v", code, out)
	}
	var n int
	_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, org).Scan(&n)
	})
	if n != 0 {
		t.Error("organization still exists after the approved deletion")
	}
}
