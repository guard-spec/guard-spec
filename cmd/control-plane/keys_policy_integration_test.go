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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Keys carry allowed addresses, the org's maximum lifetime caps and fills
// in the expiry, and a rotation makes a successor while the old key keeps
// working for the overlap and is then refused by lookup_api_key.
func TestAPIKeyPolicy(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, envOr("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	org := uuid.New()
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'kp',$2)`, org, org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO org_security (org_id, api_key_max_lifetime_days) VALUES ($1, 30)`, org)
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
	app.Get("/o/:orgId/api-keys", setOrg, listAPIKeys(db))
	app.Post("/o/:orgId/api-keys", setOrg, createAPIKey(db))
	app.Patch("/o/:orgId/api-keys/:keyId", setOrg, updateAPIKey(db))
	app.Post("/o/:orgId/api-keys/:keyId/rotate", setOrg, rotateAPIKey(db))

	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, "/o/"+org.String()+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"_raw": string(raw)}
		}
		return resp.StatusCode, out
	}
	lookup := func(raw string) (tenant.KeyInfo, error) {
		var key tenant.KeyInfo
		var project *uuid.UUID
		var cidrs []string
		err := db.QueryRow(ctx, `SELECT org_id, project_id, allowed_cidrs FROM lookup_api_key($1)`, tenant.HashKey(raw)).
			Scan(&key.OrgID, &project, &cidrs)
		key.AllowedCIDRs = tenant.ParseCIDRs(cidrs)
		return key, err
	}

	// Over the maximum lifetime: refused. Without an expiry: the maximum.
	far := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if code, out := do("POST", "/api-keys", `{"alias":"late","expires_at":"`+far+`"}`); code != 400 {
		t.Errorf("over max: %d %v", code, out)
	}
	if code, out := do("POST", "/api-keys", `{"alias":"bad","allowed_cidrs":["nope"]}`); code != 400 {
		t.Errorf("bad cidr: %d %v", code, out)
	}
	code, out := do("POST", "/api-keys", `{"alias":"edge","allowed_cidrs":["203.0.113.0/24"," 198.51.100.7 "]}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	raw1, prefix1 := out["key"].(string), out["key_prefix"].(string)
	exp, _ := time.Parse(time.RFC3339Nano, out["expires_at"].(string))
	if d := time.Until(exp); d < 29*24*time.Hour || d > 30*24*time.Hour+time.Minute {
		t.Errorf("expires_at = %v, want about 30 days", exp)
	}
	if got := out["allowed_cidrs"].([]any); len(got) != 2 || got[1] != "198.51.100.7" {
		t.Errorf("allowed_cidrs = %v", got)
	}
	key, err := lookup(raw1)
	if err != nil || key.OrgID != org || len(key.AllowedCIDRs) != 2 {
		t.Fatalf("lookup: %+v %v", key, err)
	}

	// The expiry can be moved within the maximum, not removed.
	if code, out := do("PATCH", "/api-keys/"+prefix1, `{"expires_at":null}`); code != 400 {
		t.Errorf("remove expiry under a max: %d %v", code, out)
	}
	soon := time.Now().Add(2 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if code, out := do("PATCH", "/api-keys/"+prefix1, `{"expires_at":"`+soon+`","allowed_cidrs":[]}`); code != 200 || len(out["allowed_cidrs"].([]any)) != 0 {
		t.Errorf("patch: %d %v", code, out)
	}
	if key, err := lookup(raw1); err != nil || len(key.AllowedCIDRs) != 0 {
		t.Errorf("lookup after patch: %+v %v", key, err)
	}

	// Rotation: a successor with the same alias; the old key ends at the overlap.
	code, out = do("POST", "/api-keys/"+prefix1+"/rotate", `{"overlap_hours":1}`)
	if code != 201 || out["alias"] != "edge" || out["rotated_from"] != prefix1 {
		t.Fatalf("rotate: %d %v", code, out)
	}
	raw2, prefix2 := out["key"].(string), out["key_prefix"].(string)
	if _, err := lookup(raw2); err != nil {
		t.Errorf("successor lookup: %v", err)
	}
	if _, err := lookup(raw1); err != nil {
		t.Errorf("old key refused during the overlap: %v", err)
	}
	if code, out := do("POST", "/api-keys/"+prefix1+"/rotate", ``); code != 409 {
		t.Errorf("second rotation: %d %v", code, out)
	}
	code, out = do("GET", "/api-keys", "")
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	var old map[string]any
	for _, it := range out["data"].([]any) {
		if m := it.(map[string]any); m["key_prefix"] == prefix1 {
			old = m
		}
	}
	if old == nil || old["rotated_to"] != prefix2 || old["rotated_at"] == nil {
		t.Errorf("old key in list = %v", old)
	}

	// Past the overlap, the gateway's lookup refuses the old key.
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET expires_at = NOW() - interval '1 second' WHERE key_prefix = $1`, prefix1)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lookup(raw1); err == nil {
		t.Error("expired key still resolves")
	}
	if _, err := lookup(raw2); err != nil {
		t.Errorf("successor refused: %v", err)
	}
}
