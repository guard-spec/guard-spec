//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/giaplee/guard-spec/internal/inference/ml"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires migration 009. Reads as the application role, so the store is
// checked under row-level security.
func TestDBExemplarStore(t *testing.T) {
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
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'org_exemplars')`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("database lacks migration 009_org_exemplars")
	}

	org := uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,'ex',$2)`, org, org.String())
	defer exec(`DELETE FROM organizations WHERE id = $1`, org)

	store := dbExemplarStore{db: db}
	if v, err := store.ExemplarVersion(ctx, org); err != nil || v != 0 {
		t.Fatalf("version %d, %v", v, err)
	}
	exec(`INSERT INTO org_exemplars (org_id, label, text) VALUES ($1,'block','wire money now'), ($1,'allow','hello')`, org)
	v, err := store.ExemplarVersion(ctx, org)
	if err != nil || v != 2 {
		t.Fatalf("version after two inserts %d, %v", v, err)
	}
	ex, err := store.Exemplars(ctx, org)
	if err != nil || len(ex) != 2 {
		t.Fatalf("exemplars %v, %v", ex, err)
	}
	for _, x := range ex {
		if x.Category != ml.TenantCategory || (x.Label != ml.LabelBlock && x.Label != ml.LabelAllow) {
			t.Errorf("exemplar %+v", x)
		}
	}
	// Another org's scope sees none of them.
	if ex, err := store.Exemplars(ctx, uuid.New()); err != nil || len(ex) != 0 {
		t.Fatalf("other org: %v, %v", ex, err)
	}
}
