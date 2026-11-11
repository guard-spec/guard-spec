//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// approvalHarness serves the approval handlers with the caller in X-User;
// the handlers read the caller's role and instance admin flag themselves.
type approvalHarness struct {
	t   *testing.T
	ctx context.Context
	db  *pgxpool.Pool
	app *fiber.App
}

func newApprovalHarness(t *testing.T) *approvalHarness {
	t.Helper()
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
	app := fiber.New()
	setUser := func(c *fiber.Ctx) error {
		if u, err := uuid.Parse(c.Get("X-User")); err == nil {
			c.Locals("user_id", u)
		}
		return c.Next()
	}
	setOrg := func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.SendStatus(400)
		}
		c.Locals("org_id", id)
		return setUser(c)
	}
	app.Get("/admin/approvals", setUser, listInstanceApprovals(db))
	app.Patch("/o/:orgId", setOrg, updateOrgSettings(db))
	app.Delete("/o/:orgId", setOrg, deleteOrg(db))
	app.Post("/o/:orgId/policies", setOrg, createPolicy(db, eng))
	app.Put("/o/:orgId/policies/:id", setOrg, updatePolicy(db, eng))
	app.Delete("/o/:orgId/policies/:id", setOrg, deletePolicy(db))
	app.Post("/o/:orgId/policies/:id/rollback", setOrg, rollbackPolicy(db, eng))
	app.Get("/o/:orgId/approvals", setOrg, listApprovals(db))
	app.Post("/o/:orgId/approvals/:id/approve", setOrg, approveRequest(db))
	app.Post("/o/:orgId/approvals/:id/reject", setOrg, rejectRequest(db))
	return &approvalHarness{t: t, ctx: ctx, db: db, app: app}
}

// user creates a user; instance makes them an instance administrator.
func (h *approvalHarness) user(instance bool) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	if _, err := h.db.Exec(h.ctx, `INSERT INTO users (id, email, is_instance_admin) VALUES ($1, $2, $3)`,
		id, "apr-"+id.String()[:8]+"@example.com", instance); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _, _ = h.db.Exec(h.ctx, `DELETE FROM users WHERE id = $1`, id) })
	return id
}

// org creates an organization with members (user → role) and two-person
// approval on or off.
func (h *approvalHarness) org(twoPerson bool, members map[uuid.UUID]string) uuid.UUID {
	h.t.Helper()
	org := uuid.New()
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(h.ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'two', $2)`, org, org.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(h.ctx, `INSERT INTO org_security (org_id, two_person_approval, approval_expiry_hours) VALUES ($1, $2, 2)`,
			org, twoPerson); err != nil {
			return err
		}
		for u, role := range members {
			if _, err := tx.Exec(h.ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3::org_role)`, u, org, role); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_ = tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(h.ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		})
	})
	return org
}

func (h *approvalHarness) setTwoPerson(org uuid.UUID, on bool) {
	h.t.Helper()
	h.exec(org, `UPDATE org_security SET two_person_approval = $2 WHERE org_id = $1`, org, on)
}

func (h *approvalHarness) exec(org uuid.UUID, sql string, args ...any) {
	h.t.Helper()
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(h.ctx, sql, args...)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

// do calls path, under /o/<org> unless it starts with /admin.
func (h *approvalHarness) do(org, user uuid.UUID, method, path, body string) (int, map[string]any) {
	h.t.Helper()
	if !strings.HasPrefix(path, "/admin") {
		path = "/o/" + org.String() + path
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", user.String())
	resp, err := h.app.Test(req, -1)
	if err != nil {
		h.t.Fatal(err)
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

func requestID(t *testing.T, out map[string]any) string {
	t.Helper()
	r, _ := out["request"].(map[string]any)
	id, _ := r["id"].(string)
	if id == "" {
		t.Fatalf("no request in %v", out)
	}
	return id
}

// policyState reads a policy's enabled flag, description and log_only.
func (h *approvalHarness) policyState(org uuid.UUID, id string) (enabled bool, description string, logOnly, exists bool) {
	h.t.Helper()
	var desc *string
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT enabled, description, log_only FROM policies WHERE id = $1`, id).Scan(&enabled, &desc, &logOnly)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.t.Fatal(err)
	}
	if desc != nil {
		description = *desc
	}
	return enabled, description, logOnly, err == nil
}

func (h *approvalHarness) status(org uuid.UUID, id string) (status, note string) {
	h.t.Helper()
	var n *string
	err := tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT status, decision_note FROM approval_requests WHERE id = $1`, id).Scan(&status, &n)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if n != nil {
		note = *n
	}
	return status, note
}

func (h *approvalHarness) orgExists(org uuid.UUID) bool {
	h.t.Helper()
	var n int
	_ = tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT count(*) FROM organizations WHERE id = $1`, org).Scan(&n)
	})
	return n == 1
}

const approvalRule = `{"name":"a","action":"block","condition":{"field":"scores.l2","operator":">","value":0.9}}`

func (h *approvalHarness) createPolicy(org, user uuid.UUID, name string) string {
	h.t.Helper()
	code, out := h.do(org, user, "POST", "/policies", `{"name":"`+name+`","rules":[`+approvalRule+`]}`)
	if code != 201 {
		h.t.Fatalf("create %s: %d %v", name, code, out)
	}
	return out["id"].(string)
}

// With two_person_approval on, disabling a policy and turning content
// storage on become pending requests; the requester cannot approve, another
// admin can, a rejection changes nothing, and a request past its time
// expires. Deleting a policy needs no approval but only works once the
// policy is disabled.
func TestTwoPersonApproval(t *testing.T) {
	h := newApprovalHarness(t)
	requester, approver, member := h.user(false), h.user(false), h.user(false)
	org := h.org(true, map[uuid.UUID]string{requester: "admin", approver: "admin", member: "member"})
	pID := h.createPolicy(org, requester, "guarded")

	// An enabled policy is never deleted: disabling it is the guarded step.
	code, out := h.do(org, requester, "DELETE", "/policies/"+pID, "")
	if code != 409 || out["code"] != "policy_enabled" || out["error"] != "disable the policy before deleting it" {
		t.Fatalf("delete enabled: %d %v", code, out)
	}

	// Disabling waits; the rest of the save applies.
	code, out = h.do(org, requester, "PUT", "/policies/"+pID, `{"enabled":false,"description":"d","reason":"too many blocks"}`)
	if code != 202 || out["approval_required"] != true || out["already_pending"] != false {
		t.Fatalf("disable: %d %v", code, out)
	}
	disableReq := requestID(t, out)
	if enabled, desc, _, _ := h.policyState(org, pID); !enabled || desc != "d" {
		t.Fatalf("after the request: enabled %v, description %q", enabled, desc)
	}
	// Asking again answers with the pending request.
	code, out = h.do(org, approver, "PUT", "/policies/"+pID, `{"enabled":false}`)
	if code != 202 || out["already_pending"] != true || requestID(t, out) != disableReq {
		t.Fatalf("second disable: %d %v", code, out)
	}
	code, out = h.do(org, requester, "GET", "/approvals", "")
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("pending: %d %v", code, out)
	}
	first := items[0].(map[string]any)
	if first["kind"] != approvalPolicyDisable || first["target_label"] != "guarded" || first["reason"] != "too many blocks" || first["status"] != "pending" {
		t.Errorf("pending item = %v", first)
	}
	// Still enabled: deleting stays refused while the disable waits.
	if code, out = h.do(org, approver, "DELETE", "/policies/"+pID, ""); code != 409 {
		t.Errorf("delete while the disable waits: %d %v", code, out)
	}

	// A later edit of the policy survives the approval.
	if code, out = h.do(org, approver, "PUT", "/policies/"+pID, `{"description":"later","log_only":true}`); code != 200 {
		t.Fatalf("later edit: %d %v", code, out)
	}
	if code, out = h.do(org, requester, "POST", "/approvals/"+disableReq+"/approve", ""); code != 403 || out["code"] != "self_approval" {
		t.Errorf("self approval: %d %v", code, out)
	}
	if code, out = h.do(org, member, "POST", "/approvals/"+disableReq+"/approve", ""); code != 403 || out["code"] != "forbidden" {
		t.Errorf("member approval: %d %v", code, out)
	}
	if code, out = h.do(org, approver, "POST", "/approvals/"+disableReq+"/approve", `{"note":"agreed"}`); code != 200 || out["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	enabled, desc, logOnly, _ := h.policyState(org, pID)
	if enabled || desc != "later" || !logOnly {
		t.Errorf("after approval: enabled %v, description %q, log_only %v; want the later edit kept", enabled, desc, logOnly)
	}
	if code, out = h.do(org, approver, "POST", "/approvals/"+disableReq+"/approve", ""); code != 409 || out["code"] != "approval_not_pending" {
		t.Errorf("second approval: %d %v", code, out)
	}

	// Disabled, it is deleted at once, two-person approval or not.
	if code, out = h.do(org, requester, "DELETE", "/policies/"+pID, ""); code != 204 {
		t.Fatalf("delete disabled: %d %v", code, out)
	}
	if _, _, _, exists := h.policyState(org, pID); exists {
		t.Error("disabled policy not deleted")
	}

	// A rejected disable changes nothing.
	p2 := h.createPolicy(org, requester, "kept")
	code, out = h.do(org, requester, "PUT", "/policies/"+p2, `{"enabled":false}`)
	if code != 202 {
		t.Fatalf("disable 2: %d %v", code, out)
	}
	rejectReq := requestID(t, out)
	if code, out = h.do(org, approver, "POST", "/approvals/"+rejectReq+"/reject", `{"note":"keep it"}`); code != 200 || out["status"] != "rejected" || out["decision_note"] != "keep it" {
		t.Fatalf("reject: %d %v", code, out)
	}
	if enabled, _, _, _ := h.policyState(org, p2); !enabled {
		t.Error("policy disabled despite the rejection")
	}

	// Content storage: the request expires before anyone decides.
	code, out = h.do(org, requester, "PATCH", "", `{"audit_store_content":true}`)
	if code != 202 {
		t.Fatalf("content storage: %d %v", code, out)
	}
	contentReq := requestID(t, out)
	h.exec(org, `UPDATE approval_requests SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, contentReq)
	if code, out = h.do(org, approver, "POST", "/approvals/"+contentReq+"/approve", ""); code != 409 || out["code"] != "approval_expired" {
		t.Errorf("expired approval: %d %v", code, out)
	}
	code, out = h.do(org, approver, "GET", "/approvals?status=expired", "")
	if code != 200 || len(out["items"].([]any)) != 1 {
		t.Errorf("expired list: %d %v", code, out)
	}
	// The expired request no longer holds the pending slot.
	code, out = h.do(org, requester, "PATCH", "", `{"audit_store_content":true}`)
	if code != 202 || out["already_pending"] != false || requestID(t, out) == contentReq {
		t.Errorf("new content storage request: %d %v", code, out)
	}
	var stores bool
	_ = tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT audit_store_content FROM organizations WHERE id = $1`, org).Scan(&stores)
	})
	if stores {
		t.Error("content storage turned on without approval")
	}
	// Turning it off never needs approval.
	if code, _ = h.do(org, requester, "PATCH", "", `{"audit_store_content":false}`); code != 200 {
		t.Errorf("storage off: %d", code)
	}

	// Off: the same calls apply at once; an enabled policy is still not deleted.
	h.setTwoPerson(org, false)
	if code, out = h.do(org, requester, "PATCH", "", `{"audit_store_content":true}`); code != 200 || out["audit_store_content"] != true {
		t.Errorf("storage on without two-person: %d %v", code, out)
	}
	if code, out = h.do(org, requester, "DELETE", "/policies/"+p2, ""); code != 409 || out["code"] != "policy_enabled" {
		t.Errorf("delete enabled without two-person: %d %v", code, out)
	}
	if code, _ = h.do(org, requester, "PUT", "/policies/"+p2, `{"enabled":false}`); code != 200 {
		t.Errorf("disable without two-person: %d", code)
	}
	if code, _ = h.do(org, requester, "DELETE", "/policies/"+p2, ""); code != 204 {
		t.Errorf("delete without two-person: %d", code)
	}
}

// A request whose change no longer applies is cancelled, not failed: the
// policy was deleted, or was disabled another way, before the approval.
func TestApprovalOrphansCancel(t *testing.T) {
	h := newApprovalHarness(t)
	requester, approver := h.user(false), h.user(false)
	org := h.org(true, map[uuid.UUID]string{requester: "admin", approver: "owner"})

	// Gone at approval time.
	gone := h.createPolicy(org, requester, "gone")
	code, out := h.do(org, requester, "PUT", "/policies/"+gone, `{"enabled":false}`)
	if code != 202 {
		t.Fatalf("disable gone: %d %v", code, out)
	}
	goneReq := requestID(t, out)
	h.exec(org, `DELETE FROM policies WHERE id = $1`, gone)
	code, out = h.do(org, approver, "POST", "/approvals/"+goneReq+"/approve", "")
	req, _ := out["request"].(map[string]any)
	if code != 409 || out["code"] != "approval_cancelled" || req["status"] != "cancelled" {
		t.Fatalf("approve orphan: %d %v", code, out)
	}
	if status, note := h.status(org, goneReq); status != "cancelled" || note != reasonPolicyGone {
		t.Errorf("orphan: %s %q", status, note)
	}

	// Already disabled at approval time.
	off := h.createPolicy(org, requester, "off")
	code, out = h.do(org, requester, "PUT", "/policies/"+off, `{"enabled":false}`)
	if code != 202 {
		t.Fatalf("disable off: %d %v", code, out)
	}
	offReq := requestID(t, out)
	h.exec(org, `UPDATE policies SET enabled = false WHERE id = $1`, off)
	if code, out = h.do(org, approver, "POST", "/approvals/"+offReq+"/approve", ""); code != 409 || out["code"] != "approval_cancelled" {
		t.Fatalf("approve disabled: %d %v", code, out)
	}
	if status, note := h.status(org, offReq); status != "cancelled" || note != reasonPolicyDisabled {
		t.Errorf("already disabled: %s %q", status, note)
	}

	// Disabled directly once two-person approval is off: the pending request
	// is cancelled by that save, and the policy can then be deleted.
	direct := h.createPolicy(org, requester, "direct")
	code, out = h.do(org, requester, "PUT", "/policies/"+direct, `{"enabled":false}`)
	if code != 202 {
		t.Fatalf("disable direct: %d %v", code, out)
	}
	directReq := requestID(t, out)
	h.setTwoPerson(org, false)
	if code, out = h.do(org, approver, "PUT", "/policies/"+direct, `{"enabled":false}`); code != 200 {
		t.Fatalf("direct disable: %d %v", code, out)
	}
	if status, _ := h.status(org, directReq); status != "cancelled" {
		t.Errorf("request after a direct disable: %s", status)
	}

	// Found by the list: a policy deleted under a pending request (SQL here).
	listed := h.createPolicy(org, requester, "listed")
	h.setTwoPerson(org, true)
	code, out = h.do(org, requester, "PUT", "/policies/"+listed, `{"enabled":false}`)
	if code != 202 {
		t.Fatalf("disable listed: %d %v", code, out)
	}
	listedReq := requestID(t, out)
	h.exec(org, `DELETE FROM policies WHERE id = $1`, listed)
	code, out = h.do(org, approver, "GET", "/approvals?status=cancelled", "")
	if code != 200 || len(out["items"].([]any)) != 4 {
		t.Errorf("cancelled list: %d %v", code, out)
	}
	if status, _ := h.status(org, listedReq); status != "cancelled" {
		t.Errorf("listed orphan: %s", status)
	}
	var logged int
	_ = tenant.WithOrg(h.ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, `SELECT count(*) FROM activity_log WHERE org_id = $1 AND action = 'approval.cancelled'`, org).Scan(&logged)
	})
	if logged != 4 {
		t.Errorf("approval.cancelled logged %d times, want 4", logged)
	}

	// Rolling back to a disabled version is a disable: it waits too.
	rb := h.createPolicy(org, requester, "rollback")
	h.setTwoPerson(org, false)
	if code, _ = h.do(org, requester, "PUT", "/policies/"+rb, `{"enabled":false}`); code != 200 {
		t.Fatalf("disable rb: %d", code)
	}
	if code, _ = h.do(org, requester, "PUT", "/policies/"+rb, `{"enabled":true}`); code != 200 {
		t.Fatalf("enable rb: %d", code)
	}
	h.setTwoPerson(org, true)
	code, out = h.do(org, requester, "POST", "/policies/"+rb+"/rollback", `{"reason":"back"}`)
	if code != 202 || out["approval_required"] != true {
		t.Fatalf("rollback to disabled: %d %v", code, out)
	}
	if enabled, _, _, _ := h.policyState(org, rb); !enabled {
		t.Error("rollback disabled the policy without approval")
	}
}

// Deleting an organization always takes two people: an owner asks, another
// owner or an instance administrator approves, whatever the two-person
// setting. An instance administrator may delete it at once with a reason.
func TestOrgDeletionApproval(t *testing.T) {
	h := newApprovalHarness(t)
	owner, owner2, admin, member := h.user(false), h.user(false), h.user(false), h.user(false)
	instance := h.user(true)

	// Two-person approval off: still a request.
	orgA := h.org(false, map[uuid.UUID]string{owner: "owner", owner2: "owner", admin: "admin", member: "member"})
	slugA := `{"confirm":"` + orgA.String() + `","reason":"merged into another org"}`
	if code, out := h.do(orgA, owner, "DELETE", "", `{"confirm":"wrong"}`); code != 400 || out["code"] != "confirm_mismatch" {
		t.Errorf("wrong confirm: %d %v", code, out)
	}
	if code, out := h.do(orgA, admin, "DELETE", "", slugA); code != 403 {
		t.Errorf("admin asks: %d %v", code, out)
	}
	code, out := h.do(orgA, owner, "DELETE", "", slugA)
	if code != 202 || out["approval_required"] != true {
		t.Fatalf("org delete: %d %v", code, out)
	}
	reqA := requestID(t, out)
	if code, out = h.do(orgA, owner, "DELETE", "", slugA); code != 202 || out["already_pending"] != true || requestID(t, out) != reqA {
		t.Errorf("second ask: %d %v", code, out)
	}
	if code, out = h.do(orgA, owner, "POST", "/approvals/"+reqA+"/approve", ""); code != 403 || out["code"] != "self_approval" {
		t.Errorf("self approval: %d %v", code, out)
	}
	if code, out = h.do(orgA, admin, "POST", "/approvals/"+reqA+"/approve", ""); code != 403 || out["code"] != "owner_or_instance_admin_required" {
		t.Errorf("admin approval: %d %v", code, out)
	}
	if code, out = h.do(orgA, member, "POST", "/approvals/"+reqA+"/reject", ""); code != 403 {
		t.Errorf("member rejection: %d %v", code, out)
	}
	if !h.orgExists(orgA) {
		t.Fatal("organization deleted before approval")
	}
	// The instance administrator sees it among every org's pending deletions.
	code, out = h.do(uuid.Nil, instance, "GET", "/admin/approvals", "")
	found := false
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == reqA && m["org_id"] == orgA.String() && m["payload"].(map[string]any)["slug"] == orgA.String() {
			found = true
		}
	}
	if code != 200 || !found {
		t.Errorf("instance list: %d %v", code, out)
	}
	if code, out = h.do(orgA, instance, "POST", "/approvals/"+reqA+"/approve", `{"note":"checked"}`); code != 204 {
		t.Fatalf("instance admin approval: %d %v", code, out)
	}
	if h.orgExists(orgA) {
		t.Error("organization still exists after the approved deletion")
	}

	// Another owner approves.
	orgB := h.org(true, map[uuid.UUID]string{owner: "owner", owner2: "owner"})
	code, out = h.do(orgB, owner, "DELETE", "", `{"confirm":"`+orgB.String()+`"}`)
	if code != 202 {
		t.Fatalf("org B delete: %d %v", code, out)
	}
	if code, out = h.do(orgB, owner2, "POST", "/approvals/"+requestID(t, out)+"/approve", ""); code != 204 {
		t.Fatalf("second owner approval: %d %v", code, out)
	}
	if h.orgExists(orgB) {
		t.Error("org B still exists")
	}

	// An instance administrator deletes at once, with a reason.
	orgC := h.org(false, map[uuid.UUID]string{owner: "owner"})
	if code, out = h.do(orgC, instance, "DELETE", "", `{"confirm":"`+orgC.String()+`","reason":"  "}`); code != 400 || out["code"] != "reason_required" {
		t.Errorf("no reason: %d %v", code, out)
	}
	if code, out = h.do(orgC, instance, "DELETE", "", `{"confirm":"`+orgC.String()+`","reason":"abuse report 42"}`); code != 204 {
		t.Fatalf("instance delete: %d %v", code, out)
	}
	if h.orgExists(orgC) {
		t.Error("org C still exists")
	}
	var reason string
	err := withInstanceScope(h.ctx, h.db, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx,
			`SELECT details->>'reason' FROM activity_log WHERE org_id IS NULL AND action = 'org.deleted' AND target = $1 AND actor_id = $2`,
			orgC.String(), instance).Scan(&reason)
	})
	if err != nil || reason != "abuse report 42" {
		t.Errorf("instance log reason = %q, %v", reason, err)
	}

	// The default organization is never deleted, not even by them.
	if code, out = h.do(defaultOrgID, instance, "DELETE", "", `{"confirm":"default","reason":"x"}`); code != 409 || out["code"] != "default_org" {
		t.Errorf("default org: %d %v", code, out)
	}
}

// Migration 029 cancels pending policy deletions and duplicate pending
// requests (keeping the oldest), then allows one pending request per org,
// kind and target. Its down step reads cancelled requests as expired.
func TestMigration029(t *testing.T) {
	up, err := os.ReadFile("../../migrations/029_approval_consistency.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/029_approval_consistency.down.sql")
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
		if _, err := tx.Exec(ctx, string(down)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'm', $2)`, org, org.String()); err != nil {
			return err
		}
		insert := func(kind, target, age string) (id uuid.UUID) {
			if err := tx.QueryRow(ctx,
				`INSERT INTO approval_requests (org_id, kind, target, expires_at, created_at)
				 VALUES ($1, $2, $3, NOW() + interval '1 hour', NOW() - $4::interval) RETURNING id`, org, kind, target, age).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return id
		}
		older := insert("policy.disable", "p1", "2 minutes")
		newer := insert("policy.disable", "p1", "1 minute")
		other := insert("policy.disable", "p2", "1 minute")
		del := insert("policy.delete", "p3", "1 minute")
		if _, err := tx.Exec(ctx, string(up)); err != nil {
			return err
		}
		for id, want := range map[uuid.UUID]string{older: "pending", newer: "cancelled", other: "pending", del: "cancelled"} {
			var got string
			if err := tx.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, id).Scan(&got); err != nil {
				return err
			}
			if got != want {
				t.Errorf("%s: %s, want %s", id, got, want)
			}
		}
		// The index refuses a second pending request for p2.
		_, err := tx.Exec(ctx, `SAVEPOINT dup`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO approval_requests (org_id, kind, target, expires_at) VALUES ($1, 'policy.disable', 'p2', NOW() + interval '1 hour')`, org)
		if err == nil || !strings.Contains(err.Error(), "approval_requests_one_pending") {
			t.Errorf("duplicate pending insert: %v", err)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT dup`); err != nil {
			return err
		}
		// Down again: cancelled reads as expired under 027's check.
		if _, err := tx.Exec(ctx, string(down)); err != nil {
			return err
		}
		var expired int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE org_id = $1 AND status = 'expired'`, org).Scan(&expired); err != nil {
			return err
		}
		if expired != 2 {
			t.Errorf("expired after down: %d, want 2", expired)
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

// Through the real routes: an instance administrator reaches an org they
// are not a member of to list, approve and delete; anyone else outside it
// does not, and inside it an admin still cannot ask to delete it.
func TestOrgDeletionRoutes(t *testing.T) {
	h := newCPHarness(t)
	org, _, ownerTok := h.org(auth.RoleOwner)
	adminTok := h.member(org, auth.RoleAdmin)
	instTok, _ := h.instanceAdmin()
	outsider, _ := h.user("outsider-password-123")
	base := "/v1/organizations/" + org.String()
	confirm := `{"confirm":"` + org.String() + `"}`

	h.expect(403, "DELETE", base, outsider, confirm)
	h.expect(403, "DELETE", base, adminTok, confirm)
	req := h.expect(202, "DELETE", base, ownerTok, confirm)["request"].(map[string]any)
	h.expect(403, "GET", base+"/approvals", outsider, "")
	if items := h.expect(200, "GET", base+"/approvals", instTok, "")["items"].([]any); len(items) != 1 {
		t.Errorf("instance admin list: %v", items)
	}
	h.expect(403, "GET", "/v1/admin/approvals", ownerTok, "")
	h.expect(200, "GET", "/v1/admin/approvals", instTok, "")
	h.expect(403, "POST", base+"/approvals/"+req["id"].(string)+"/approve", adminTok, "")
	h.expect(204, "POST", base+"/approvals/"+req["id"].(string)+"/approve", instTok, "")

	// Direct deletion by an instance administrator, with a reason.
	org2, _, _ := h.org(auth.RoleOwner)
	base2 := "/v1/organizations/" + org2.String()
	h.expect(400, "DELETE", base2, instTok, `{"confirm":"`+org2.String()+`"}`)
	h.expect(204, "DELETE", base2, instTok, `{"confirm":"`+org2.String()+`","reason":"cleanup"}`)
}
