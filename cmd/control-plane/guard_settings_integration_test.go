//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Guard settings round-trip through the handlers as the application role,
// including the org's block thresholds, which may only be stricter than the
// gateway's (0, 0.85].
func TestGuardSettingsThresholds(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, envOr("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	org := uuid.New()
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'gs',$2)`, org, org.String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		})
	})

	app := fiber.New()
	setOrg := func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.SendStatus(400)
		}
		c.Locals("org_id", id)
		return c.Next()
	}
	app.Get("/o/:orgId/guard-settings", setOrg, getGuardSettings(db))
	app.Put("/o/:orgId/guard-settings", setOrg, putGuardSettings(db))

	do := func(method, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, "/o/"+org.String()+"/guard-settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	for _, bad := range []string{`{"injection_threshold":0.9}`, `{"injection_threshold":0}`, `{"indirect_threshold":-1}`,
		`{"indirect_threshold":"0.5"}`, `{"block_threshold":0.5}`} {
		if code, body := do("PUT", bad); code != 400 {
			t.Errorf("%s: status %d %s, want 400", bad, code, body)
		}
	}

	in := `{"scan_roles":{"system":true},"spotlight":"delimit","indirect_action":"redact","injection_threshold":0.7,"indirect_threshold":0.6}`
	if code, body := do("PUT", in); code != 200 {
		t.Fatalf("put: %d %s", code, body)
	}
	code, body := do("GET", "")
	if code != 200 {
		t.Fatalf("get: %d %s", code, body)
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(in), &want)
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("get = %s, want %s", gotJSON, wantJSON)
	}

	// Leaving a threshold out clears it.
	if code, body := do("PUT", `{"spotlight":"off"}`); code != 200 {
		t.Fatalf("put: %d %s", code, body)
	}
	if _, body := do("GET", ""); strings.Contains(body, "threshold") {
		t.Errorf("thresholds kept: %s", body)
	}
}
