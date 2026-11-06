//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// The dashboard aggregates only the org's requests in the window, as the
// application role (row level security applies).
func TestDashboard(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	other, _, otherToken := h.org(auth.RoleAdmin)
	project, rule := uuid.New(), uuid.New()
	err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, 'billing', 'billing')`, project, org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name, rules) VALUES ($1, 'strict', $2)`, org,
			`[{"id":"`+rule.String()+`","name":"l1 high","action":"block","condition":{"field":"scores.l1","operator":">=","value":0.9}}]`); err != nil {
			return err
		}
		// Five requests in the last day, one three days ago.
		_, err := tx.Exec(ctx,
			`INSERT INTO requests (org_id, project_id, action, rule_id, injection_label, latency_ms, created_at) VALUES
			   ($1, $2, 'allow', NULL, 'BENIGN',    10, NOW() - interval '1 hour'),
			   ($1, $2, 'block', $3,   'JAILBREAK', 20, NOW() - interval '2 hours'),
			   ($1, $2, 'allow', NULL, NULL,        30, NOW() - interval '3 hours'),
			   ($1, NULL, 'block', $3, 'jailbreak', 40, NOW() - interval '4 hours'),
			   ($1, NULL, 'route', NULL, 'injection', NULL, NOW() - interval '5 hours'),
			   ($1, $2, 'allow', NULL, NULL,      1000, NOW() - interval '3 days')`, org, project, rule)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Another org's traffic never shows.
	err = tenant.WithOrg(ctx, h.db, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO requests (org_id, action, latency_ms) VALUES ($1, 'block', 5), ($1, 'block', 5)`, other)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/organizations/" + org.String() + "/dashboard"

	status, body := h.do("GET", base, viewer, "")
	if status != 200 {
		t.Fatalf("status %d: %v", status, body)
	}
	if body["window"] != "24h" || body["bucket"] != "hour" || body["total"] != float64(5) || body["blocked"] != float64(2) ||
		body["block_rate"] != 0.4 || body["project_id"] != nil {
		t.Errorf("totals: %v", body)
	}
	lat := body["latency_ms"].(map[string]any)
	if lat["p50"] != float64(25) || lat["p99"].(float64) < 39 || lat["p99"].(float64) > 40 {
		t.Errorf("latency: %v", lat)
	}
	counts := func(key, name string) map[string]float64 {
		out := map[string]float64{}
		for _, x := range body[key].([]any) {
			row := x.(map[string]any)
			k, _ := row[name].(string)
			out[k] = row["count"].(float64)
		}
		return out
	}
	if got := counts("by_action", "action"); len(got) != 3 || got["allow"] != 2 || got["block"] != 2 || got["route"] != 1 {
		t.Errorf("by_action: %v", got)
	}
	if got := counts("top_labels", "label"); len(got) != 2 || got["jailbreak"] != 2 || got["injection"] != 1 {
		t.Errorf("top_labels: %v", got)
	}
	rules := body["top_rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("top_rules: %v", rules)
	}
	if r := rules[0].(map[string]any); r["rule_id"] != rule.String() || r["rule"] != "l1 high" || r["policy"] != "strict" || r["count"] != float64(2) {
		t.Errorf("top rule: %v", r)
	}
	projects := body["top_projects"].([]any)
	if len(projects) != 2 {
		t.Fatalf("top_projects: %v", projects)
	}
	if p := projects[0].(map[string]any); p["project_id"] != project.String() || p["name"] != "billing" || p["count"] != float64(3) || p["blocked"] != float64(1) {
		t.Errorf("first project: %v", p)
	}
	if p := projects[1].(map[string]any); p["project_id"] != nil || p["name"] != nil || p["count"] != float64(2) || p["blocked"] != float64(1) {
		t.Errorf("no project: %v", p)
	}
	series := body["series"].([]any)
	var sum, blocked float64
	for _, b := range series {
		sum += b.(map[string]any)["count"].(float64)
		blocked += b.(map[string]any)["blocked"].(float64)
	}
	if len(series) != 25 || sum != 5 || blocked != 2 {
		t.Errorf("series: %d buckets, %v requests, %v blocked", len(series), sum, blocked)
	}

	// A week holds the older row too, by day.
	_, body = h.do("GET", base+"?window=7d", viewer, "")
	if body["bucket"] != "day" || body["total"] != float64(6) || len(body["series"].([]any)) != 8 {
		t.Errorf("7d: %v", body)
	}
	// One project.
	_, body = h.do("GET", base+"?project_id="+project.String(), viewer, "")
	if body["total"] != float64(3) || body["blocked"] != float64(1) || body["project_id"] != project.String() {
		t.Errorf("project: %v", body)
	}

	// Nothing matches (the project is another org's): zeros, null
	// percentiles, empty lists.
	_, body = h.do("GET", "/v1/organizations/"+other.String()+"/dashboard?window=30d&project_id="+project.String(), otherToken, "")
	if body["total"] != float64(0) || body["block_rate"] != float64(0) || body["latency_ms"].(map[string]any)["p50"] != nil {
		t.Errorf("empty: %v", body)
	}
	for _, k := range []string{"by_action", "top_labels", "top_rules", "top_projects"} {
		if l, ok := body[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %v, want []", k, body[k])
		}
	}

	for _, tc := range []struct {
		path, token string
		want        int
	}{
		{base + "?window=90d", viewer, 400},
		{base + "?project_id=nope", viewer, 400},
		{base, "", 401},
		{base, otherToken, 403},
	} {
		if status, body := h.do("GET", tc.path, tc.token, ""); status != tc.want {
			t.Errorf("%s: %d %v, want %d", tc.path, status, body, tc.want)
		}
	}
}
