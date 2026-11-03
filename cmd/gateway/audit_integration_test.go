//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/outputguard"
	"github.com/promptshield/promptshield/internal/tenant"
)

// Requires the compose stack. The audit row carries the new actions and the
// output guard counts, and never the content.
func TestAuditRowWithOutputCounts(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://ps_app:ps_app@localhost:5432/promptshield?sslmode=disable"
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

	logRequest(db, requestEntry{OrgID: org, Model: "m", Action: actionOutputLeak,
		Output: outputguard.Counts{"canary": 1, "email": 2}})
	logRequest(db, requestEntry{OrgID: org, Model: "m", Action: actionError})

	type row struct {
		action string
		tags   []string
	}
	var rows []row
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT action, pii_entities FROM requests WHERE org_id = $1 ORDER BY created_at`, org)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.action, &x.tags); err != nil {
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
}
