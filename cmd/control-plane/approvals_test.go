// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/jackc/pgx/v5"
)

func TestApprovalErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{pgx.ErrNoRows, 404, ""},
		{errApprovalNotPending, 409, "approval_not_pending"},
		{errApprovalExpired, 409, "approval_expired"},
		{errApprovalTargetGone, 409, "approval_target_gone"},
		{errSelfApproval, 403, "self_approval"},
		{errOrgDeleteApprover, 403, "owner_or_instance_admin_required"},
		{errNotOrgAdmin, 403, "forbidden"},
		{errors.New("other"), 0, ""},
		{nil, 0, ""},
	} {
		status, _ := approvalError(tc.err)
		if status != tc.status || approvalCode(tc.err) != tc.code {
			t.Errorf("%v: status %d code %q, want %d %q", tc.err, status, approvalCode(tc.err), tc.status, tc.code)
		}
	}
	for _, kind := range approvalKinds {
		if effectAction(kind) == "approval.applied" {
			t.Errorf("%s has no effect action", kind)
		}
	}
}

// Who may decide what: an organization's deletion takes another owner or an
// instance administrator; everything else an admin of the org. Anyone who may
// approve may reject, and a requester may always withdraw.
func TestMayDecide(t *testing.T) {
	for _, tc := range []struct {
		kind               string
		role               auth.Role
		instance, approve  bool
		requester, allowed bool
	}{
		{kind: approvalOrgDelete, role: auth.RoleOwner, approve: true, allowed: true},
		{kind: approvalOrgDelete, instance: true, approve: true, allowed: true},
		{kind: approvalOrgDelete, role: auth.RoleAdmin, approve: true},
		{kind: approvalOrgDelete, role: auth.RoleAdmin, allowed: true},
		{kind: approvalOrgDelete, role: auth.RoleMember, requester: true, allowed: true},
		{kind: approvalOrgDelete, role: auth.RoleMember},
		{kind: approvalPolicyDisable, role: auth.RoleAdmin, approve: true, allowed: true},
		{kind: approvalPolicyDisable, role: auth.RoleOwner, approve: true, allowed: true},
		{kind: approvalPolicyDisable, role: auth.RoleMember, approve: true},
		{kind: approvalPolicyDisable, instance: true, approve: true},
		{kind: approvalPolicyDisable, instance: true},
		{kind: approvalContentStorage, role: auth.RoleViewer, requester: true, allowed: true},
	} {
		err := mayDecide(tc.kind, tc.role, tc.instance, tc.approve, tc.requester)
		if (err == nil) != tc.allowed {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestDecisionNote(t *testing.T) {
	app := fiber.New()
	var got string
	var gotErr error
	app.Post("/", func(c *fiber.Ctx) error {
		got, gotErr = decisionNote(c)
		return c.SendStatus(200)
	})
	post := func(body string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	post(``)
	if got != "" || gotErr != nil {
		t.Errorf("empty body: %q %v", got, gotErr)
	}
	post(`{"note":"  looks fine  "}`)
	if got != "looks fine" || gotErr != nil {
		t.Errorf("note: %q %v", got, gotErr)
	}
	post(`{"note":"` + strings.Repeat("x", maxApprovalNoteRunes+1) + `"}`)
	if gotErr == nil {
		t.Error("long note accepted")
	}
	post(`nope`)
	if gotErr == nil {
		t.Error("invalid body accepted")
	}
}
