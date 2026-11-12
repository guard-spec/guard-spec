//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// The CSV report counts requests, actions, block reasons, projects and
// keys per period, for the org only, with no content; a viewer may read it.
func TestRequestsReport(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	other, _, _ := h.org(auth.RoleAdmin)
	project, rule := uuid.New(), uuid.New()
	keyRaw := "gs_" + strings.Repeat("a", 24) + uuid.New().String()[:8]
	err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, 'billing', 'billing')`, project, org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_keys (key_hash, key_prefix, org_id) VALUES ($1, $2, $3)`, tenant.HashKey(keyRaw), keyRaw[:11], org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name, rules) VALUES ($1, 'strict', $2)`, org,
			`[{"id":"`+rule.String()+`","name":"l1 high","action":"block","condition":{"field":"scores.l1","operator":">=","value":0.9}}]`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO requests (org_id, project_id, api_key_hash, action, rule_id, injection_label, request_content, created_at) VALUES
			   ($1, $2, $4, 'allow', NULL, 'BENIGN', 'SECRET PROMPT', NOW() - interval '1 hour'),
			   ($1, $2, $4, 'block', $3,   'JAILBREAK', 'SECRET PROMPT', NOW() - interval '2 hours'),
			   ($1, NULL, NULL, 'block', NULL, 'jailbreak', NULL, NOW() - interval '3 hours'),
			   ($1, NULL, NULL, 'block', NULL, NULL, NULL, NOW() - interval '4 hours'),
			   ($1, NULL, NULL, 'route', NULL, NULL, NULL, NOW() - interval '5 hours'),
			   ($1, $2, NULL, 'allow', NULL, NULL, NULL, NOW() - interval '3 days')`, org, project, rule, tenant.HashKey(keyRaw))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tenant.WithOrg(ctx, h.db, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO requests (org_id, action) VALUES ($1, 'block'), ($1, 'block')`, other)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	status, body := h.raw("GET", "/v1/organizations/"+org.String()+"/reports/requests.csv?window=30d", viewer, "", "")
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	if strings.Contains(body, "SECRET") {
		t.Fatal("the report carries request content")
	}
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(records[0], ",") != strings.Join(reportHeader, ",") {
		t.Errorf("header = %v", records[0])
	}
	sum := map[string][2]int{} // section/key -> requests, blocked over all periods
	for _, r := range records[1:] {
		k := r[2] + "/" + r[3]
		var n, b int
		_, _ = fmtSscan(r[4], &n)
		_, _ = fmtSscan(r[5], &b)
		sum[k] = [2]int{sum[k][0] + n, sum[k][1] + b}
	}
	want := map[string][2]int{
		"total/all": {6, 3}, "action/allow": {2, 0}, "action/block": {3, 3}, "action/route": {1, 0},
		"reason/policy:l1 high": {1, 1}, "reason/jailbreak": {1, 1}, "reason/other": {1, 1},
		"project/billing": {3, 1}, "project/none": {3, 2},
		"api_key/" + keyRaw[:11]: {2, 1}, "api_key/none": {4, 2},
	}
	for k, w := range want {
		if sum[k] != w {
			t.Errorf("%s = %v, want %v", k, sum[k], w)
		}
	}
	if len(sum) != len(want) {
		t.Errorf("sections = %v", sum)
	}

	// 24h leaves the old row out; a bad range is refused.
	_, body = h.raw("GET", "/v1/organizations/"+org.String()+"/reports/requests.csv", viewer, "", "")
	if !strings.Contains(body, ",total,all,") || strings.Contains(body, ",6,") {
		t.Errorf("24h report: %s", body)
	}
	if status, _ := h.raw("GET", "/v1/organizations/"+org.String()+"/reports/requests.csv?window=1y", viewer, "", ""); status != 400 {
		t.Errorf("bad window: %d", status)
	}
}

// fmtSscan parses a decimal, as fmt.Sscan would, without the import.
func fmtSscan(s string, n *int) (int, error) {
	v := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, nil
		}
		v = v*10 + int(r-'0')
	}
	*n = v
	return 1, nil
}
