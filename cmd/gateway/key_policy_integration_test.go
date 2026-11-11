//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Through the database lookup: an expired key and a key limited to another
// network are refused at the gateway, in the usual auth error shape; a
// revoked key too. The allowed addresses come from lookup_api_key
// (migration 028).
func TestKeyPolicyAtGateway(t *testing.T) {
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
	keys := map[string]string{"live": "", "expired": "", "revoked": "", "elsewhere": "", "local": ""}
	for name := range keys {
		keys[name] = "gs_" + strings.Repeat("0", 24) + uuid.New().String()[:8]
	}
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'kp',$2)`, org, org.String()); err != nil {
			return err
		}
		for name, raw := range keys {
			expires, revoked, cidrs := "NULL", "NULL", "'{}'"
			switch name {
			case "expired":
				expires = "NOW() - interval '1 minute'"
			case "revoked":
				revoked = "NOW()"
			case "elsewhere":
				cidrs = "'{203.0.113.0/24}'"
			case "local":
				cidrs = "'{0.0.0.0/0,::/0}'" // fiber's Test has no peer: 0.0.0.0
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO api_keys (key_hash, key_prefix, org_id, expires_at, revoked_at, allowed_cidrs)
				 VALUES ($1, $2, $3, `+expires+`, `+revoked+`, `+cidrs+`)`, tenant.HashKey(raw), raw[:11], org); err != nil {
				return err
			}
		}
		return nil
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

	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(testGateway(t, runner), dbKeyLookup(db))
	for name, want := range map[string]int{"live": 200, "local": 200, "expired": 401, "revoked": 401, "elsewhere": 403, "unknown": 401} {
		raw := keys[name]
		if name == "unknown" {
			raw = "gs_not_a_key"
		}
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", raw)
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s key: status %d, want %d", name, resp.StatusCode, want)
		}
	}
}
