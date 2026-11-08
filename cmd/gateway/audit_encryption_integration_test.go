//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/datakey"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

func testKeyring(t *testing.T) *datakey.Keyring {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	keys, err := datakey.ParseLocal("it:" + base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := datakey.NewKeyring(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// Content is sealed with the org's data key: the database holds no plain
// text, the key is made once per org, and only for orgs that store content.
func TestAuditContentEncryption(t *testing.T) {
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
	var migrated bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('org_data_keys') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("database lacks migration 021_org_data_keys")
	}

	const prompt = `{"messages":[{"role":"user","content":"số CCCD 012345678901"}]}`
	const answer = `{"choices":[{"message":{"content":"đã nhận"}}]}`
	newOrg := func(optIn bool) uuid.UUID {
		org := uuid.New()
		if err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug, audit_store_content) VALUES ($1, 'enc', $2, $3)`, org, org.String(), optIn)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return org
	}
	type stored struct {
		req, resp, reqSHA, respSHA *string
		keys                       int
	}
	read := func(org uuid.UUID) stored {
		var s stored
		if err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT request_content, response_content, request_sha256, response_sha256
				FROM requests WHERE org_id = $1`, org).Scan(&s.req, &s.resp, &s.reqSHA, &s.respSHA); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM org_data_keys WHERE org_id = $1`, org).Scan(&s.keys)
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ring := testKeyring(t)
	content := auditContent{keys: datakey.NewStore(ring)}

	t.Run("opted-in org: sealed, opens with the org key", func(t *testing.T) {
		org := newOrg(true)
		if err := insertRequest(db, content, requestEntry{OrgID: org, Action: actionAllow, Request: prompt, Response: answer}); err != nil {
			t.Fatal(err)
		}
		s := read(org)
		if s.req == nil || !datakey.IsSealed(*s.req) || strings.Contains(*s.req, "012345678901") {
			t.Fatalf("request_content not sealed: %v", s.req)
		}
		if s.resp == nil || !datakey.IsSealed(*s.resp) || s.keys != 1 {
			t.Fatalf("response_content %v, %d keys", s.resp, s.keys)
		}
		// A fresh store (another process) opens it through the database.
		other := datakey.NewStore(ring)
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			got, err := other.Open(ctx, tx, org, *s.req, datakey.ContentAAD(org, "request_content", *s.reqSHA))
			if err != nil || got != prompt {
				t.Errorf("open request: %q %v", got, err)
			}
			if _, err := other.Open(ctx, tx, org, *s.req, datakey.ContentAAD(org, "response_content", *s.reqSHA)); err == nil {
				t.Error("opened with the other column's additional data")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// A second row reuses the active key.
		if err := insertRequest(db, content, requestEntry{OrgID: org, Action: actionAllow, Request: prompt}); err != nil {
			t.Fatal(err)
		}
		var n int
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM org_data_keys WHERE org_id = $1`, org).Scan(&n)
		})
		if n != 1 {
			t.Errorf("%d data keys after two rows, want 1", n)
		}
	})

	t.Run("org without content storage: no content, no key", func(t *testing.T) {
		org := newOrg(false)
		if err := insertRequest(db, content, requestEntry{OrgID: org, Action: actionAllow, Request: prompt, Response: answer}); err != nil {
			t.Fatal(err)
		}
		if s := read(org); s.req != nil || s.resp != nil || s.keys != 0 || s.reqSHA == nil {
			t.Fatalf("got content %v / %v, %d keys, sha %v", s.req, s.resp, s.keys, s.reqSHA)
		}
	})

	t.Run("AUDIT_STORE_CONTENT for every org", func(t *testing.T) {
		org := newOrg(false)
		all := auditContent{all: true, keys: content.keys}
		if err := insertRequest(db, all, requestEntry{OrgID: org, Action: actionAllow, Request: prompt}); err != nil {
			t.Fatal(err)
		}
		if s := read(org); s.req == nil || !datakey.IsSealed(*s.req) {
			t.Fatalf("request_content %v", s.req)
		}
	})

	t.Run("a KEK that fails: the row is kept without content", func(t *testing.T) {
		org := newOrg(true)
		broken, _ := datakey.NewKeyring(&failingKEK{})
		bad := auditContent{keys: datakey.NewStore(broken)}
		if err := insertRequest(db, bad, requestEntry{OrgID: org, Action: actionBlock, Request: prompt}); err != nil {
			t.Fatal(err)
		}
		if s := read(org); s.req != nil || s.reqSHA == nil || s.keys != 0 {
			t.Fatalf("content %v sha %v keys %d", s.req, s.reqSHA, s.keys)
		}
	})

	t.Run("concurrent first rows make one key", func(t *testing.T) {
		org := newOrg(true)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Separate stores: no shared cache, as with several gateways.
				c := auditContent{keys: datakey.NewStore(ring)}
				if err := insertRequest(db, c, requestEntry{OrgID: org, Action: actionAllow, Request: prompt}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		var keys, rows int
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM org_data_keys WHERE org_id = $1`, org).Scan(&keys)
			return tx.QueryRow(ctx, `SELECT count(*) FROM requests WHERE org_id = $1 AND request_content LIKE 'gsenc:v1:%'`, org).Scan(&rows)
		})
		if keys != 1 || rows != 8 {
			t.Fatalf("%d keys, %d sealed rows", keys, rows)
		}
	})
}

type failingKEK struct{}

func (failingKEK) ID() string { return "local:broken" }
func (failingKEK) Wrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, os.ErrDeadlineExceeded
}
func (failingKEK) Unwrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, os.ErrDeadlineExceeded
}
