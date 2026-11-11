// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
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
