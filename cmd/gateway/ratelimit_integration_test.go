//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/ratelimit"
	"github.com/promptshield/promptshield/internal/tenant"
)

// Requires the compose stack. Connects as the application role.
func TestKeyLimitsFromDatabase(t *testing.T) {
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

	org, other := uuid.New(), uuid.New()
	limited, inherits := uuid.NewString(), uuid.NewString()
	for _, o := range []uuid.UUID{org, other} {
		err := tenant.WithOrg(ctx, db, o, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'k',$2)`, o, o.String())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO api_keys (key_hash, key_prefix, org_id, rpm_limit, tpm_limit)
			VALUES ($1,'ps_x',$2,5,0)`, limited, org); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO api_keys (key_hash, key_prefix, org_id) VALUES ($1,'ps_y',$2)`, inherits, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// A negative limit is refused by the database too.
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET rpm_limit = -1 WHERE key_hash = $1`, limited)
		return err
	})
	if err == nil {
		t.Error("negative rpm_limit accepted")
	}

	r := newRateLimiter(ratelimit.Limits{RPM: 100, TPM: 1000}, dbKeyLimits(db))
	if got := r.limits(ctx, org, limited); got != (ratelimit.Limits{RPM: 5, TPM: 0}) {
		t.Errorf("own limits = %+v, want rpm 5 and unlimited tokens", got)
	}
	if got := r.limits(ctx, org, inherits); got != (ratelimit.Limits{RPM: 100, TPM: 1000}) {
		t.Errorf("NULL limits = %+v, want the defaults", got)
	}
	// RLS: under another org the key is invisible, so the defaults apply.
	if _, _, err := dbKeyLimits(db)(ctx, other, limited); err == nil {
		t.Error("another org read the key's limits")
	}
}
