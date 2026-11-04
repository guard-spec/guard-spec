//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GET /v1/organizations lists the caller's memberships, and nobody else's.
func TestListMyOrgs(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	orgA, userA, tokenA := h.org(auth.RoleAdmin)
	orgB, _, tokenB := h.org(auth.RoleOwner)
	orgC, _, _ := h.org(auth.RoleOwner) // a third org neither caller is in
	// A is also a viewer of B.
	err := tenant.WithOrg(ctx, h.db, orgB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1,$2,'viewer')`, userA, orgB)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	roles := func(token string) map[string]string {
		t.Helper()
		status, body := h.do("GET", "/v1/organizations", token, "")
		if status != 200 {
			t.Fatalf("status %d: %v", status, body)
		}
		out := map[string]string{}
		for _, r := range body["data"].([]any) {
			row := r.(map[string]any)
			if row["name"] == nil || row["slug"] == nil {
				t.Errorf("row lacks name or slug: %v", row)
			}
			out[row["id"].(string)] = row["role"].(string)
		}
		return out
	}

	a := roles(tokenA)
	if len(a) != 2 || a[orgA.String()] != "admin" || a[orgB.String()] != "viewer" {
		t.Errorf("user A sees %v; want %s admin and %s viewer", a, orgA, orgB)
	}
	b := roles(tokenB)
	if len(b) != 1 || b[orgB.String()] != "owner" {
		t.Errorf("user B sees %v; want only %s owner", b, orgB)
	}
	for _, seen := range []map[string]string{a, b} {
		if _, ok := seen[orgC.String()]; ok {
			t.Errorf("an org the caller is not in is listed: %s", orgC)
		}
	}

	// A user with no membership gets an empty list, not someone else's.
	other, err := auth.IssueToken(testSecret, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if got := roles(other); len(got) != 0 {
		t.Errorf("user without memberships sees %v", got)
	}
	if status, _ := h.do("GET", "/v1/organizations", "", ""); status != 401 {
		t.Errorf("without a token: %d", status)
	}
}

// Older or hand-written audit rows may hold NULL scores and flags.
func TestRequestsListNullScores(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO requests (org_id, action) VALUES ($1, 'allow')`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.do("GET", "/v1/organizations/"+org.String()+"/requests", admin, "")
	if status != 200 {
		t.Fatalf("status %d: %v", status, body)
	}
	rows := body["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	row := rows[0].(map[string]any)
	for _, k := range []string{"injection_score", "toxicity_score", "anomaly_score"} {
		if row[k] != float64(0) {
			t.Errorf("%s = %v, want 0", k, row[k])
		}
	}
	for _, k := range []string{"had_tag_chars", "had_bidi"} {
		if row[k] != false {
			t.Errorf("%s = %v, want false", k, row[k])
		}
	}
}

// A policy can be created disabled, so it is never live in between.
func TestCreatePolicyEnabled(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String() + "/policies"
	rule := `[{"name":"r","action":"block","condition":{"field":"scores.l1","operator":">=","value":0.9}}]`
	for _, tc := range []struct{ name, extra string }{
		{"off", `,"enabled":false`},
		{"on", `,"enabled":true`},
		{"default", ``},
	} {
		if status, body := h.do("POST", base, admin, `{"name":"`+tc.name+`","rules":`+rule+tc.extra+`}`); status != 201 {
			t.Fatalf("%s: %d %v", tc.name, status, body)
		}
	}
	_, body := h.do("GET", base, admin, "")
	enabled := map[string]bool{}
	for _, p := range body["data"].([]any) {
		row := p.(map[string]any)
		enabled[row["name"].(string)] = row["enabled"].(bool)
	}
	if enabled["off"] || !enabled["on"] || !enabled["default"] {
		t.Errorf("enabled = %v", enabled)
	}
}
