//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// The impact preview counts identical inputs, the rule's decisions and the
// detector's refusals at or below a score over 7 days, in the org only,
// without content.
func TestRequestImpact(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	other, _, _ := h.org(auth.RoleAdmin)
	rule := uuid.New()
	ids := map[string]uuid.UUID{}
	insert := func(o uuid.UUID, name, sql string, args ...any) {
		t.Helper()
		id := uuid.New()
		err := tenant.WithOrg(ctx, h.db, o, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO requests (id, org_id, action, rule_id, injection_label, injection_score, request_sha256,
			   pii_entities, request_content, created_at) `+sql, append([]any{id, o}, args...)...)
			return err
		})
		if err != nil {
			t.Fatal(name, err)
		}
		ids[name] = id
	}
	const row = `VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'SECRET', NOW() - $9::interval)`
	insert(org, "fp", row, "block", nil, "jailbreak", 0.62, "h1", []string{"detector:l1=0.620"}, "1 hour")
	insert(org, "fp-again", row, "block", nil, "jailbreak", 0.62, "h1", nil, "2 hours")
	insert(org, "same-allowed", row, "allow", nil, nil, 0.1, "h1", nil, "3 hours")
	insert(org, "same-old", row, "block", nil, "jailbreak", 0.62, "h1", nil, "10 days")
	insert(org, "lower", row, "block", nil, "role_play", 0.5, "h2", nil, "1 hour")
	insert(org, "higher", row, "block", nil, "jailbreak", 0.9, "h3", nil, "1 hour")
	insert(org, "unscanned", row, "block", nil, "unscanned_content", 0, "h4", nil, "1 hour")
	insert(org, "by-rule", row, "block", rule, nil, 0.2, nil, nil, "1 hour")
	insert(org, "rule-logged", row, "log", rule, nil, 0.2, nil, nil, "1 hour")
	insert(other, "other", row, "block", nil, "jailbreak", 0.3, "h1", nil, "1 hour")
	h.exec(org, `UPDATE organizations SET guard_settings = '{"injection_threshold": 0.6}' WHERE id = $1`, org)

	get := func(name string) (int, map[string]any) {
		return h.do("GET", "/v1/organizations/"+org.String()+"/requests/"+ids[name].String()+"/impact", viewer, "")
	}
	code, out := get("fp")
	req, _ := out["request"].(map[string]any)
	same, _ := out["same_input"].(map[string]any)
	th, _ := out["threshold"].(map[string]any)
	if code != 200 || out["window"] != "7d" || req["decided_by"] != "detector" || req["has_hash"] != true ||
		same["total"] != float64(3) || same["blocked"] != float64(2) || out["same_rule"] != nil ||
		th["org"] != 0.6 || th["above_default"] != false || th["at_or_below"] != float64(3) {
		t.Fatalf("detector: %d %v", code, out)
	}
	if _, body := h.raw("GET", "/v1/organizations/"+org.String()+"/requests/"+ids["fp"].String()+"/impact", viewer, "", ""); strings.Contains(body, "SECRET") {
		t.Fatal("the preview carries content")
	}
	if _, out = get("higher"); out["threshold"].(map[string]any)["above_default"] != true {
		t.Errorf("above the gateway's threshold: %v", out)
	}
	_, out = get("by-rule")
	sr, _ := out["same_rule"].(map[string]any)
	if out["request"].(map[string]any)["decided_by"] != "rule" || out["same_input"] != nil || out["threshold"] != nil ||
		sr["total"] != float64(2) || sr["blocked"] != float64(1) {
		t.Errorf("rule: %v", out)
	}
	if _, out = get("unscanned"); out["request"].(map[string]any)["decided_by"] != "input" || out["threshold"] != nil {
		t.Errorf("unscanned: %v", out)
	}
	if _, out = get("same-allowed"); out["request"].(map[string]any)["decided_by"] != "none" {
		t.Errorf("allowed: %v", out)
	}
	if code, _ := h.do("GET", "/v1/organizations/"+org.String()+"/requests/"+ids["other"].String()+"/impact", viewer, ""); code != 404 {
		t.Errorf("another org's request: %d", code)
	}
	if code, _ := h.do("GET", "/v1/organizations/"+org.String()+"/requests/nope/impact", viewer, ""); code != 404 {
		t.Errorf("bad id: %d", code)
	}
}

// exec runs sql in org's scope.
func (h *cpHarness) exec(org uuid.UUID, sql string, args ...any) {
	h.t.Helper()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
}
