//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack. The audit row carries the new actions and the
// output guard counts, and never the content.
func TestAuditRowWithOutputCounts(t *testing.T) {
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
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'a',$2)`, org, org.String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	logRequest(db, false, requestEntry{OrgID: org, Model: "m", Action: actionOutputLeak,
		Output:  outputguard.Counts{"canary": 1, "email": 2},
		Request: `{"q":"secret"}`, Response: `{"a":"leaked canary"}`})
	logRequest(db, false, requestEntry{OrgID: org, Model: "m", Action: actionError, Request: `{"q":"x"}`})

	type row struct {
		action                  string
		tags                    []string
		reqHash, respHash       *string
		reqContent, respContent *string
	}
	var rows []row
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT action, pii_entities, request_sha256, response_sha256, request_content, response_content
			 FROM requests WHERE org_id = $1 ORDER BY created_at`, org)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.action, &x.tags, &x.reqHash, &x.respHash, &x.reqContent, &x.respContent); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return r.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].action != "output_leak" || len(rows[0].tags) != 2 ||
		rows[0].tags[0] != "output:canary=1" || rows[0].tags[1] != "output:email=2" ||
		rows[1].action != "error" || rows[1].tags != nil {
		t.Errorf("rows = %+v", rows)
	}
	// Audit privacy (D6) covers these actions too: digests, never content.
	for _, r := range rows {
		if r.reqHash == nil || r.reqContent != nil || r.respContent != nil {
			t.Errorf("%s row: request hash %v, content %v / %v", r.action, r.reqHash, r.reqContent, r.respContent)
		}
	}
	if len(rows) == 2 && (rows[0].respHash == nil || rows[1].respHash != nil) {
		t.Errorf("response hashes = %v, %v", rows[0].respHash, rows[1].respHash)
	}
}
