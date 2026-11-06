//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// The shadow comparison aggregates the org's shadow_results in the window, as
// the application role; the disagreement list is for admins.
func TestShadowComparison(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	admin := h.member(org, auth.RoleAdmin)
	other, _, otherAdmin := h.org(auth.RoleAdmin)

	type row struct {
		status         string
		active, shadow *float64
		ad, sd         *string
		ago            string
	}
	f := func(v float64) *float64 { return &v }
	s := func(v string) *string { return &v }
	rows := []row{
		{"ok", f(0.10), f(0.12), s("allow"), s("allow"), "1 hour"},
		{"ok", f(0.20), f(0.90), s("allow"), s("block"), "2 hours"}, // would block
		{"ok", f(0.95), f(0.40), s("block"), s("allow"), "3 hours"}, // would allow
		{"ok", f(0.97), f(0.99), s("block"), s("block"), "4 hours"},
		{"timeout", f(0.30), nil, nil, nil, "5 hours"},
		{"skipped", nil, nil, nil, nil, "6 hours"},
		{"ok", f(0.10), f(0.95), s("allow"), s("block"), "3 days"}, // outside 24h
	}
	insert := func(o uuid.UUID, rs []row) {
		err := tenant.WithOrg(ctx, h.db, o, func(tx pgx.Tx) error {
			for _, r := range rs {
				id := uuid.New()
				if _, err := tx.Exec(ctx, `INSERT INTO requests (id, org_id, action, model, created_at)
					VALUES ($1, $2, 'allow', 'gpt-4o', NOW() - $3::interval)`, id, o, r.ago); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO shadow_results (request_id, org_id, status, active_model, shadow_model,
					active_score, shadow_score, active_decision, shadow_decision, texts, created_at)
					VALUES ($1, $2, $3, 'guardspec-classifier@v3b', 'guardspec-classifier@v2', $4, $5, $6, $7, 1,
					        NOW() - $8::interval)`, id, o, r.status, r.active, r.shadow, r.ad, r.sd, r.ago); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(org, rows)
	insert(other, rows[:2]) // another org's rows never show

	base := "/v1/organizations/" + org.String() + "/shadow"
	status, body := h.do("GET", base, viewer, "")
	if status != 200 {
		t.Fatalf("summary %d: %v", status, body)
	}
	if body["total"] != float64(6) || body["compared"] != float64(4) || body["agree"] != float64(2) ||
		body["agreement_rate"] != 0.5 || body["shadow_would_block"] != float64(1) || body["shadow_would_allow"] != float64(1) ||
		body["threshold"] != 0.85 {
		t.Errorf("summary: %v", body)
	}
	nc := body["not_compared"].(map[string]any)
	if nc["timeout"] != float64(1) || nc["skipped"] != float64(1) || nc["error"] != float64(0) {
		t.Errorf("not_compared: %v", nc)
	}
	pairs := body["pairs"].([]any)
	if len(pairs) != 1 || pairs[0].(map[string]any)["count"] != float64(6) {
		t.Errorf("pairs: %v", pairs)
	}
	scores := body["scores"].(map[string]any)
	active := scores["active"].(map[string]any)
	if m := active["mean"].(float64); math.Abs(m-(0.10+0.20+0.95+0.97)/4) > 1e-6 {
		t.Errorf("active mean %v", m)
	}
	hist := scores["histogram"].([]any)
	var na, ns float64
	for _, b := range hist {
		na += b.(map[string]any)["active"].(float64)
		ns += b.(map[string]any)["shadow"].(float64)
	}
	if len(hist) != 10 || na != 4 || ns != 4 || hist[9].(map[string]any)["active"] != float64(2) {
		t.Errorf("histogram: %v", hist)
	}
	if _, body := h.do("GET", base+"?window=7d", viewer, ""); body["total"] != float64(7) {
		t.Errorf("7d total: %v", body["total"])
	}
	if status, _ := h.do("GET", base+"?window=1y", viewer, ""); status != 400 {
		t.Errorf("bad window: %d", status)
	}

	// Disagreements: admins only; newest first; filtered by direction.
	list := base + "/disagreements"
	if status, _ := h.do("GET", list, viewer, ""); status != 403 {
		t.Errorf("viewer listed disagreements: %d", status)
	}
	if status, _ := h.do("GET", list, otherAdmin, ""); status != 403 {
		t.Errorf("another org's admin listed disagreements: %d", status)
	}
	status, body = h.do("GET", list, admin, "")
	items, _ := body["items"].([]any)
	if status != 200 || len(items) != 2 {
		t.Fatalf("disagreements %d: %v", status, body)
	}
	first := items[0].(map[string]any)
	if first["direction"] != "would_block" || first["active_decision"] != "allow" || first["shadow_decision"] != "block" ||
		first["action"] != "allow" || first["model"] != "gpt-4o" || first["request_content"] != nil {
		t.Errorf("first: %v", first)
	}
	_, body = h.do("GET", list+"?direction=would_allow", admin, "")
	if items := body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["direction"] != "would_allow" {
		t.Errorf("would_allow: %v", body)
	}
	_, body = h.do("GET", list+"?limit=1", admin, "")
	next, _ := body["next_cursor"].(string)
	if len(body["items"].([]any)) != 1 || next == "" {
		t.Fatalf("page 1: %v", body)
	}
	_, body = h.do("GET", list+"?limit=1&cursor="+next, admin, "")
	if items := body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["direction"] != "would_allow" || body["next_cursor"] != nil {
		t.Errorf("page 2: %v", body)
	}
	if status, _ := h.do("GET", list+"?direction=sideways", admin, ""); status != 400 {
		t.Errorf("bad direction: %d", status)
	}

	// Rows go with their request (audit retention deletes requests).
	var n int
	err := tenant.WithOrg(ctx, h.db, other, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM requests WHERE org_id = $1`, other); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM shadow_results WHERE org_id = $1`, other).Scan(&n)
	})
	if err != nil || n != 0 {
		t.Errorf("after deleting the requests: %d rows, %v", n, err)
	}
}

func TestGatewayModelsNotConfigured(t *testing.T) {
	h := newCPHarness(t)
	_, _, viewer := h.org(auth.RoleViewer)
	status, body := h.do("GET", "/v1/gateway/models", viewer, "")
	if status != 200 || body["configured"] != false || body["reachable"] != false {
		t.Errorf("%d %v", status, body)
	}
	if status, _ := h.do("GET", "/v1/gateway/models", "", ""); status != 401 {
		t.Errorf("anonymous: %d", status)
	}
}
