//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// Stored content is read one row at a time, by the org's content_read_role,
// with a reason when required, and every read is in the activity log.
func TestRequestContentAccess(t *testing.T) {
	ctx := context.Background()
	h := newCPHarness(t)
	org, _, owner := h.org(auth.RoleOwner)
	viewer := h.member(org, auth.RoleViewer)
	admin := h.member(org, auth.RoleAdmin)
	var withContent, without uuid.UUID
	if err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO requests (org_id, action, request_content) VALUES ($1, 'allow', 'số thẻ 4111') RETURNING id`, org).Scan(&withContent); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO requests (org_id, action) VALUES ($1, 'allow') RETURNING id`, org).Scan(&without)
	}); err != nil {
		t.Fatal(err)
	}
	path := func(id uuid.UUID) string {
		return "/v1/organizations/" + org.String() + "/requests/" + id.String() + "/content"
	}
	views := func() []map[string]any {
		t.Helper()
		var out []map[string]any
		_ = tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT target, details->>'reason' FROM activity_log WHERE org_id = $1 AND action = 'request.content_viewed' ORDER BY seq`, org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var target string
				var reason *string
				_ = rows.Scan(&target, &reason)
				out = append(out, map[string]any{"target": target, "reason": reason})
			}
			return nil
		})
		return out
	}

	// Default policy: admin, with a reason.
	if st, body := h.do("POST", path(withContent), viewer, `{"reason":"điều tra sự cố"}`); st != 403 || body["code"] != "content_read_role" {
		t.Fatalf("viewer: %d %v", st, body)
	}
	if st, body := h.do("POST", path(withContent), admin, `{}`); st != 400 || body["code"] != "reason_required" {
		t.Fatalf("no reason: %d %v", st, body)
	}
	if st, body := h.do("POST", path(withContent), admin, `{"reason":"  x "}`); st != 400 {
		t.Fatalf("a one-letter reason: %d %v", st, body)
	}
	if len(views()) != 0 {
		t.Fatalf("refused reads were logged: %v", views())
	}
	st, body := h.do("POST", path(withContent), admin, `{"reason":"điều tra sự cố #42"}`)
	if st != 200 || body["request_content"] != "số thẻ 4111" {
		t.Fatalf("admin: %d %v", st, body)
	}
	if v := views(); len(v) != 1 || v[0]["target"] != "request "+withContent.String() || *(v[0]["reason"].(*string)) != "điều tra sự cố #42" {
		t.Fatalf("activity: %v", v)
	}
	if st, _ := h.do("POST", path(without), admin, `{"reason":"điều tra"}`); st != 404 {
		t.Fatalf("a row without content: %d", st)
	}
	if st, _ := h.do("POST", path(uuid.New()), admin, `{"reason":"điều tra"}`); st != 404 {
		t.Fatalf("an unknown row: %d", st)
	}

	// The owner opens it to viewers, without a reason.
	st, body = h.do("PUT", "/v1/organizations/"+org.String()+"/security", owner,
		`{"session_lifetime_hours":12,"content_read_role":"viewer","content_view_reason":false}`)
	if st != 200 || body["content_read_role"] != "viewer" || body["content_view_reason"] != false {
		t.Fatalf("security: %d %v", st, body)
	}
	if st, body := h.do("POST", path(withContent), viewer, ``); st != 200 || body["request_content"] != "số thẻ 4111" {
		t.Fatalf("viewer without a reason: %d %v", st, body)
	}
	if v := views(); len(v) != 2 || v[1]["reason"].(*string) != nil {
		t.Fatalf("activity: %v", v)
	}
	if st, _ := h.do("PUT", "/v1/organizations/"+org.String()+"/security", owner, `{"content_read_role":"guest"}`); st != 400 {
		t.Fatalf("bad role accepted: %d", st)
	}
	// A client from before: the fields left out read as the defaults.
	_, body = h.do("PUT", "/v1/organizations/"+org.String()+"/security", owner, `{"session_lifetime_hours":12}`)
	if body["content_read_role"] != "admin" || body["content_view_reason"] != true {
		t.Fatalf("defaults: %v", body)
	}
}
