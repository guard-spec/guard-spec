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

// The security overview's lists: the projects and API keys with the most
// refused requests, refused ones only, with the key's prefix and alias.
func TestDashboardMostAttacked(t *testing.T) {
	h := newCPHarness(t)
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	project := uuid.New()
	keyA := "gs_" + strings.Repeat("b", 24) + uuid.New().String()[:8]
	keyB := "gs_" + strings.Repeat("c", 24) + uuid.New().String()[:8]
	hashA, hashB := tenant.HashKey(keyA), tenant.HashKey(keyB)
	err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, 'billing', 'billing')`, []any{project, org}},
			{`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id) VALUES ($1, $2, 'chatbot', $3)`, []any{hashA, keyA[:11], org}},
			{`INSERT INTO api_keys (key_hash, key_prefix, org_id) VALUES ($1, $2, $3)`, []any{hashB, keyB[:11], org}},
			{`INSERT INTO requests (org_id, project_id, api_key_hash, action) VALUES
			   ($1, $2, $3, 'block'), ($1, $2, $3, 'block'), ($1, $2, $3, 'allow'),
			   ($1, NULL, $4, 'block'), ($1, NULL, $4, 'allow'), ($1, NULL, NULL, 'allow')`, []any{org, project, hashA, hashB}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out := h.do("GET", "/v1/organizations/"+org.String()+"/dashboard", viewer, "")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	keys, _ := out["top_blocked_keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys: %v", out["top_blocked_keys"])
	}
	first, second := keys[0].(map[string]any), keys[1].(map[string]any)
	if first["key_prefix"] != keyA[:11] || first["alias"] != "chatbot" || first["blocked"] != float64(2) || first["count"] != float64(3) ||
		second["key_prefix"] != keyB[:11] || second["alias"] != nil || second["blocked"] != float64(1) {
		t.Errorf("keys: %v", keys)
	}
	projects, _ := out["top_blocked_projects"].([]any)
	if len(projects) != 2 || projects[0].(map[string]any)["name"] != "billing" || projects[0].(map[string]any)["blocked"] != float64(2) ||
		projects[1].(map[string]any)["project_id"] != nil {
		t.Errorf("projects: %v", projects)
	}
	// A key with no refusal is not listed; neither is a new org's anything.
	other, _, otherViewer := h.org(auth.RoleViewer)
	_, out = h.do("GET", "/v1/organizations/"+other.String()+"/dashboard", otherViewer, "")
	if k, _ := out["top_blocked_keys"].([]any); len(k) != 0 {
		t.Errorf("empty org: %v", out["top_blocked_keys"])
	}
}
