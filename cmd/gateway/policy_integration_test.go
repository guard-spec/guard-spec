//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/tenant"
)

// Requires the compose stack. Connects as the application role.
func TestPolicyLoader(t *testing.T) {
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

	org, other, project, otherProject := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ids := map[string]uuid.UUID{}
	insert := func(tx pgx.Tx, orgID uuid.UUID, name string, proj *uuid.UUID, enabled bool) error {
		id := uuid.New()
		ids[name] = id
		_, err := tx.Exec(ctx, `INSERT INTO policies (id, org_id, project_id, name, enabled) VALUES ($1,$2,$3,$4,$5)`,
			id, orgID, proj, name, enabled)
		return err
	}
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'p',$2)`, org, org.String()); err != nil {
			return err
		}
		for _, p := range []uuid.UUID{project, otherProject} {
			if _, err := tx.Exec(ctx, `INSERT INTO projects (id, org_id, name, slug) VALUES ($1,$2,'p',$3)`, p, org, p.String()); err != nil {
				return err
			}
		}
		for _, step := range []struct {
			name    string
			proj    *uuid.UUID
			enabled bool
		}{
			{"org-wide", nil, true},
			{"disabled", nil, false},
			{"project", &project, true},
			{"other-project", &otherProject, true},
		} {
			if err := insert(tx, org, step.name, step.proj, step.enabled); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tenant.WithOrg(ctx, db, other, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'p',$2)`, other, other.String()); err != nil {
			return err
		}
		return insert(tx, other, "foreign", nil, true)
	})
	if err != nil {
		t.Fatal(err)
	}

	load := dbPolicyLoader(db)
	got, err := load(ctx, org, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != ids["project"] || got[1].ID != ids["org-wide"] {
		t.Errorf("project key: got %+v", got)
	}
	got, err = load(ctx, org, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ids["org-wide"] {
		t.Errorf("org key: got %+v", got)
	}
}
