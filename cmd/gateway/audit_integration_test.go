//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack with migration 006. Connects as the application role.
func TestAuditPrivacy(t *testing.T) {
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
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'requests' AND column_name = 'request_sha256')`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("database lacks migration 006_audit_privacy")
	}

	const prompt = `{"messages":[{"role":"user","content":"my secret"}]}`
	const answer = `{"choices":[{"message":{"content":"ok"}}]}`
	sum := sha256.Sum256([]byte(prompt))
	wantHash := hex.EncodeToString(sum[:])

	newOrg := func(optIn bool) uuid.UUID {
		org := uuid.New()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug, audit_store_content)
				VALUES ($1, 'audit', $2, $3)`, org, org.String(), optIn)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return org
	}
	type row struct {
		reqHash, reqContent, respContent *string
		reqBytes, respBytes              *int
	}
	read := func(org uuid.UUID) row {
		var r row
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT request_sha256, request_bytes, request_content,
				response_bytes, response_content FROM requests WHERE org_id = $1`, org).
				Scan(&r.reqHash, &r.reqBytes, &r.reqContent, &r.respBytes, &r.respContent)
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	entry := func(org uuid.UUID) requestEntry {
		return requestEntry{OrgID: org, Action: actionAllow, Request: prompt, Response: answer}
	}

	t.Run("default stores digests only", func(t *testing.T) {
		org := newOrg(false)
		logRequest(db, false, entry(org))
		r := read(org)
		if r.reqHash == nil || *r.reqHash != wantHash {
			t.Errorf("request_sha256 = %v, want %s", r.reqHash, wantHash)
		}
		if r.reqBytes == nil || *r.reqBytes != len(prompt) || r.respBytes == nil || *r.respBytes != len(answer) {
			t.Errorf("lengths = %v, %v", r.reqBytes, r.respBytes)
		}
		if r.reqContent != nil || r.respContent != nil {
			t.Errorf("content stored without opt-in: %v / %v", r.reqContent, r.respContent)
		}
	})

	t.Run("org opt-in stores content", func(t *testing.T) {
		org := newOrg(true)
		logRequest(db, false, entry(org))
		r := read(org)
		if r.reqContent == nil || *r.reqContent != prompt || r.respContent == nil || *r.respContent != answer {
			t.Errorf("content = %v / %v", r.reqContent, r.respContent)
		}
	})

	t.Run("gateway setting stores content", func(t *testing.T) {
		org := newOrg(false)
		logRequest(db, true, entry(org))
		if r := read(org); r.reqContent == nil || *r.reqContent != prompt {
			t.Errorf("request_content = %v", r.reqContent)
		}
	})
}
