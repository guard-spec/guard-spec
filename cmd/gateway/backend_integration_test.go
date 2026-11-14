// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/backend"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires migration 031. A custom backend's configuration comes back from
// the database as stored, and the schema ties it to provider custom.
func TestBackendLoader(t *testing.T) {
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
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'o',$2)`, org, org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO upstreams (org_id, name, base_url, provider, backend)
			VALUES ($1, 'search', 'http://search:8080/api', 'custom',
			  '{"path_prefixes":["/search"],"methods":["POST"],"key_header":"X-Key",
			    "scan":{"request":["$.query"],"response":["$.results[*].snippet"],"all_strings":false,"raw_text":true}}'),
			       ($1, 'chat', 'http://ollama:11434/v1', 'ollama', NULL)`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	load := dbUpstreamLoader(db)
	up, _, err := load(ctx, org, uuid.Nil, "search")
	if err != nil {
		t.Fatal(err)
	}
	if up.Provider != backend.Provider || up.Backend == nil || up.Backend.KeyHeader != "X-Key" || !up.Backend.Scan.RawText {
		t.Fatalf("loaded %+v %+v", up, up.Backend)
	}
	if err := up.Backend.Validate(); err != nil || len(up.Backend.RequestPaths()) != 1 {
		t.Errorf("validate: %v", err)
	}
	if chat, _, err := load(ctx, org, uuid.Nil, "chat"); err != nil || chat.Backend != nil {
		t.Errorf("chat: %+v %v", chat, err)
	}

	for _, bad := range []string{
		`INSERT INTO upstreams (org_id, name, base_url, provider) VALUES ($1, 'b1', 'http://x', 'custom')`,
		`INSERT INTO upstreams (org_id, name, base_url, provider, backend) VALUES ($1, 'b2', 'http://x', 'openai', '{}')`,
		`INSERT INTO upstreams (org_id, name, base_url, provider, backend) VALUES ($1, 'b3', 'http://x', 'custom', '[]')`,
	} {
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, bad, org)
			return err
		})
		if err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}
