//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Large inputs end to end with Postgres, as the application role: the org's
// max_scan_tokens (organizations.guard_settings) lowers MAX_SCAN_TOKENS for
// the next request, a large request within the caps is scanned on the long
// path and forwarded, one over a cap or with a payload is refused and never
// forwarded, and each gets its audit row.
func TestLargeInputWithPostgres(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"
	}
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	org := uuid.New()
	inOrg := func(sql string, args ...any) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	inOrg(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'large', $2)`, org, org.String())
	t.Cleanup(func() {
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM requests WHERE org_id = $1`, org); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		})
	})

	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	up := newFakeUpstream(t, okUpstream)
	gw := testGateway(t, runner)
	cfg := defaultScanConfig()
	cfg.MaxScanTokens, cfg.ScanTokens = 100_000, 100_000
	gw.scan, gw.large = &cfg, largeLaneFor(cfg.MaxScanTokens, laneConfig(1))
	gw.policies, gw.settings = dbPolicyLoader(db), dbSettingsLoader(db)
	gw.audit = newAuditLog(func(e requestEntry) { logRequest(db, false, e) })
	if gw.upstream, err = proxy.New(proxy.Config{BaseURL: up.URL + "/v1"}); err != nil {
		t.Fatal(err)
	}
	app := newApp(gw, func(context.Context, string) (uuid.UUID, uuid.UUID, error) { return org, uuid.Nil, nil })
	send := func(body string) int {
		t.Helper()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "test")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		gw.audit.wait()
		return resp.StatusCode
	}
	lastRow := func() (action string) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT action FROM requests WHERE org_id = $1
				ORDER BY created_at DESC LIMIT 1`, org).Scan(&action)
		})
		if err != nil {
			t.Fatal(err)
		}
		return action
	}

	doc := benignDoc(200_000) // 50k tokens: past today's 28 KB, within 100k
	for _, step := range []struct {
		name     string
		settings string
		body     string
		status   int
		action   string
	}{
		{"no org cap", `{}`, largeChat(doc), 200, actionAllow},
		{"payload at the end", `{}`, largeChat(doc + " " + largeAttack), 400, actionBlock},
		{"org cap below the request", `{"max_scan_tokens":20000}`, largeChat(doc), 413, actionBlock},
		{"org cap above the gateway's", `{"max_scan_tokens":5000000}`, largeChat(benignDoc(480_000)), 413, actionBlock},
		{"org cap removed", `{}`, largeChat(doc), 200, actionAllow},
	} {
		inOrg(`UPDATE organizations SET guard_settings = $1::jsonb WHERE id = $2`, step.settings, org)
		if status := send(step.body); status != step.status {
			t.Errorf("%s: status %d, want %d", step.name, status, step.status)
		}
		if action := lastRow(); action != step.action {
			t.Errorf("%s: row %s, want %s", step.name, action, step.action)
		}
	}
	if up.hits.Load() != 2 {
		t.Fatalf("upstream hits %d, want 2", up.hits.Load())
	}
	// A bad value is refused when read, and the request fails closed.
	inOrg(`UPDATE organizations SET guard_settings = '{"max_scan_tokens":0}'::jsonb WHERE id = $1`, org)
	if status := send(largeChat("hello")); status != 503 {
		t.Errorf("invalid max_scan_tokens: status %d, want 503", status)
	}
}
