//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/indirect"
	"github.com/promptshield/promptshield/internal/tenant"
)

// Requires migration 007. Connects as the application role, so the loader is
// checked under row-level security.
func TestOrgGuardSettings(t *testing.T) {
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

	var migrated bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'organizations' AND column_name = 'guard_settings')`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("database lacks migration 007_org_guard_settings")
	}

	newOrg := func(settings *string) uuid.UUID {
		org := uuid.New()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if settings == nil {
				_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'scan', $2)`, org, org.String())
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug, guard_settings)
				VALUES ($1, 'scan', $2, $3::jsonb)`, org, org.String(), *settings)
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
		return org
	}
	load := dbSettingsLoader(db)

	plain := newOrg(nil)
	s, err := load(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if roles, mode := s.Apply(indirect.DefaultRoles, indirect.ModeOff); roles != indirect.DefaultRoles || mode != indirect.ModeOff {
		t.Errorf("default org changed settings: %+v %s", roles, mode)
	}

	custom := `{"scan_roles":{"system":true},"spotlight":"delimit"}`
	org := newOrg(&custom)
	s, err = load(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	roles, mode := s.Apply(indirect.DefaultRoles, indirect.ModeOff)
	if !roles.System || !roles.User || mode != indirect.ModeDelimit {
		t.Errorf("custom org settings: %+v %s", roles, mode)
	}

	// A stored value the gateway cannot read fails closed rather than falling
	// back to the defaults.
	bad := `{"spotlight":"loud"}`
	if _, err := load(ctx, newOrg(&bad)); err == nil {
		t.Error("invalid stored settings were accepted")
	}

	// The column only takes objects.
	err = tenant.WithOrg(ctx, db, plain, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organizations SET guard_settings = '[]'::jsonb WHERE id = $1`, plain)
		return err
	})
	if err == nil {
		t.Error("a non-object guard_settings was stored")
	}
}
