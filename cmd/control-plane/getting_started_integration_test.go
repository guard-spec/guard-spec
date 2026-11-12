//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// The checklist counts the org's own setup only, reads the layers from the
// gateway's /readyz, and is open to a viewer.
func TestGettingStarted(t *testing.T) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ready","version":"0.8.0","detector":{"layers":["l1","l2"]}}`))
	}))
	defer gw.Close()
	h := newCPHarness(t, func(s *appSettings) { s.gatewayURL = gw.URL })
	ctx := context.Background()
	org, _, viewer := h.org(auth.RoleViewer)
	other, _, _ := h.org(auth.RoleAdmin)
	path := "/v1/organizations/" + org.String() + "/getting-started"

	code, out := h.do("GET", path, viewer, "")
	up, _ := out["upstream"].(map[string]any)
	models, _ := out["models"].(map[string]any)
	if code != 200 || out["complete"] != false || up["configured"] != false || up["reachable"] != nil ||
		out["api_keys"] != float64(0) || out["policies"] != float64(0) || out["alert_channels"] != float64(0) ||
		out["input_settings"] != false || models["reachable"] != true || models["version"] != "0.8.0" {
		t.Fatalf("new org: %d %v", code, out)
	}

	// Another org's setup does not count.
	err := tenant.WithOrg(ctx, h.db, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO upstreams (org_id, name, base_url) VALUES ($1, 'main', 'https://api.example.com/v1')`, other)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		for _, q := range []string{
			`INSERT INTO upstreams (org_id, name, base_url) VALUES ($1, 'main', 'https://api.example.com/v1')`,
			`INSERT INTO upstreams (org_id, name, base_url, enabled) VALUES ($1, 'off', 'https://api.example.com/v1', false)`,
			`INSERT INTO api_keys (key_hash, key_prefix, org_id) VALUES ('h-` + org.String() + `', 'gs_live1234', $1)`,
			`INSERT INTO api_keys (key_hash, key_prefix, org_id, revoked_at) VALUES ('r-` + org.String() + `', 'gs_gone1234', $1, NOW())`,
			`INSERT INTO policies (org_id, name, rules) VALUES ($1, 'on', '[]')`,
			`INSERT INTO policies (org_id, name, rules, enabled) VALUES ($1, 'off', '[]', false)`,
			`INSERT INTO notification_channels (org_id, name, kind) VALUES ($1, 'ops', 'webhook')`,
			`INSERT INTO org_input_settings (org_id, input_mode) VALUES ($1, 'text_only')`,
			`INSERT INTO requests (org_id, action, created_at) VALUES ($1, 'error', NOW() - interval '2 hours')`,
			`INSERT INTO requests (org_id, action, response_sha256, created_at) VALUES ($1, 'allow', 'abc', NOW() - interval '1 hour')`,
			`INSERT INTO requests (org_id, action, response_sha256, request_content, created_at) VALUES ($1, 'allow', 'abc', 'SECRET', NOW() - interval '30 days')`,
		} {
			if _, err := tx.Exec(ctx, q, org); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out = h.do("GET", path, viewer, "")
	up, _ = out["upstream"].(map[string]any)
	if code != 200 || out["complete"] != true || up["upstreams"] != float64(1) || up["configured"] != true || up["reachable"] != true ||
		out["api_keys"] != float64(1) || out["policies"] != float64(1) || out["alert_channels"] != float64(1) || out["input_settings"] != true {
		t.Fatalf("set up: %d %v", code, out)
	}
	if _, body := h.raw("GET", path, viewer, "", ""); strings.Contains(body, "SECRET") {
		t.Fatal("the checklist carries request content")
	}

	// A later failure turns reachable false.
	err = tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO requests (org_id, action, created_at) VALUES ($1, 'error', NOW())`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, out = h.do("GET", path, viewer, ""); out["upstream"].(map[string]any)["reachable"] != false {
		t.Errorf("after a failure: %v", out["upstream"])
	}
	if code, _ := h.do("GET", "/v1/organizations/"+other.String()+"/getting-started", viewer, ""); code != 403 {
		t.Errorf("another org: %d", code)
	}
}
