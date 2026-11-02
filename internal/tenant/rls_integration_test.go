//go:build integration

package tenant

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack. Connects as the application role.
func TestRowLevelSecurity(t *testing.T) {
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

	orgA, orgB := uuid.New(), uuid.New()
	for _, org := range []uuid.UUID{orgA, orgB} {
		err := WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'rls', $2)`,
				org, org.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name) VALUES ($1, 'p')`, org)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	count := func(table string, tx pgx.Tx) int {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	err = WithOrg(ctx, db, orgA, func(tx pgx.Tx) error {
		// No WHERE org_id on purpose: RLS alone must hide the other tenant.
		if n := count("policies", tx); n != 1 {
			t.Errorf("policies visible = %d, want 1", n)
		}
		if n := count("organizations", tx); n != 1 {
			t.Errorf("organizations visible = %d, want 1", n)
		}
		tag, err := tx.Exec(ctx, `UPDATE policies SET name = 'x' WHERE org_id = $1`, orgB)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("updated %d rows of another org", tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Writing into another tenant is rejected.
	err = WithOrg(ctx, db, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name) VALUES ($1, 'p')`, orgB)
		return err
	})
	if err == nil {
		t.Error("expected insert into another org to fail")
	}

	// Without a tenant context the query must fail, not return rows.
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM policies`).Scan(&n); err == nil {
		t.Errorf("expected an error without app.org_id, got %d rows", n)
	}

	// The role must not bypass RLS.
	var bypass bool
	if err := db.QueryRow(ctx,
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		t.Fatal(err)
	}
	if bypass {
		t.Error("application role bypasses RLS")
	}
}
