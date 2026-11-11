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
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every save records a version; the history lists them, two versions diff,
// and a rollback (one step or to a chosen version) restores the content as a
// new version. log_only round-trips and is what the gateway's loader reads.
func TestPolicyVersionsAndRollback(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, envOr("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}

	org := uuid.New()
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'pv',$2)`, org, org.String())
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
	app.Post("/o/:orgId/policies", setOrg, createPolicy(db, eng))
	app.Put("/o/:orgId/policies/:id", setOrg, updatePolicy(db, eng))
	app.Get("/o/:orgId/policies/:id/versions", setOrg, listPolicyVersions(db))
	app.Get("/o/:orgId/policies/:id/versions/diff", setOrg, diffPolicyVersions(db))
	app.Post("/o/:orgId/policies/:id/rollback", setOrg, rollbackPolicy(db, eng))

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

	ruleA := `{"name":"a","action":"block","condition":{"field":"scores.l2","operator":">","value":0.9}}`
	ruleB := `{"name":"b","action":"log","condition":{"field":"scores.l2","operator":">","value":0.5}}`
	code, out := do("POST", "/policies", `{"name":"versioned","rules":[`+ruleA+`],"reason":"first"}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	code, out = do("PUT", "/policies/"+id, `{"rules":[`+ruleA+`,`+ruleB+`],"log_only":true,"reason":"try it"}`)
	if code != 200 || out["version"].(float64) != 2 {
		t.Fatalf("update: %d %v", code, out)
	}

	versions := func() []map[string]any {
		t.Helper()
		code, out := do("GET", "/policies/"+id+"/versions", "")
		if code != 200 {
			t.Fatalf("versions: %d %v", code, out)
		}
		items := out["items"].([]any)
		list := make([]map[string]any, len(items))
		for i, it := range items {
			list[i] = it.(map[string]any)
		}
		return list
	}
	vs := versions()
	if len(vs) != 2 || vs[0]["version"].(float64) != 2 || vs[1]["version"].(float64) != 1 {
		t.Fatalf("versions = %v", vs)
	}
	if vs[0]["kind"] != "update" || vs[0]["reason"] != "try it" || vs[0]["log_only"] != true || vs[1]["kind"] != "create" || vs[1]["reason"] != "first" {
		t.Errorf("versions = %v", vs)
	}
	if n := len(vs[0]["rules"].([]any)); n != 2 {
		t.Errorf("version 2 has %d rules, want 2", n)
	}

	code, out = do("GET", "/policies/"+id+"/versions/diff?from=1&to=2", "")
	if code != 200 || len(out["rules"].([]any)) != 1 || len(out["fields"].([]any)) != 1 {
		t.Errorf("diff: %d %v", code, out)
	}

	// The gateway's loader sees log_only.
	var logOnly bool
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT log_only FROM policies WHERE id = $1`, id).Scan(&logOnly)
	})
	if err != nil || !logOnly {
		t.Errorf("log_only stored = %v, err %v", logOnly, err)
	}

	// One step back: version 3 is what version 1 was.
	code, out = do("POST", "/policies/"+id+"/rollback", `{"reason":"too strict"}`)
	if code != 200 || out["version"].(float64) != 3 || out["rolled_back_to"].(float64) != 1 {
		t.Fatalf("rollback: %d %v", code, out)
	}
	vs = versions()
	if len(vs) != 3 || vs[0]["kind"] != "rollback" || vs[0]["rolled_back_to"].(float64) != 1 || vs[0]["log_only"] != false ||
		len(vs[0]["rules"].([]any)) != 1 || vs[0]["reason"] != "too strict" {
		t.Errorf("after rollback: %v", vs[0])
	}
	code, out = do("GET", "/policies/"+id+"/versions/diff?from=1&to=3", "")
	if code != 200 || len(out["rules"].([]any)) != 0 || len(out["fields"].([]any)) != 0 {
		t.Errorf("diff 1..3 = %d %v, want no change", code, out)
	}

	// To a chosen version: back to 2, as version 4.
	code, out = do("POST", "/policies/"+id+"/rollback", `{"version":2}`)
	if code != 200 || out["version"].(float64) != 4 || out["rolled_back_to"].(float64) != 2 {
		t.Fatalf("rollback to 2: %d %v", code, out)
	}
	if vs = versions(); len(vs[0]["rules"].([]any)) != 2 || vs[0]["log_only"] != true {
		t.Errorf("version 4 = %v", vs[0])
	}
	if code, _ = do("POST", "/policies/"+id+"/rollback", `{"version":9}`); code != 404 {
		t.Errorf("unknown version: %d", code)
	}
	if code, _ = do("POST", "/policies/"+uuid.New().String()+"/rollback", ``); code != 404 {
		t.Errorf("unknown policy: %d", code)
	}
}
