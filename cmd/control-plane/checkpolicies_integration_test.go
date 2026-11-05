//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack. The policy is written as the application role and
// checked as the owner role, the way an operator runs the pre-flight.
func TestPolicyCheckAgainstDatabase(t *testing.T) {
	ctx := context.Background()
	appURL := envOr("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable")
	ownerURL := envOr("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable")

	db, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close) // after the cleanup below, which needs the pool

	org, policyID := uuid.New(), uuid.New()
	rules := `[{"id":"` + uuid.NewString() + `","name":"toxic","action":"block",` +
		`"condition":{"field":"topic.categories","operator":"contains","value":"x"}}]`
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'c',$2)`, org, org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO policies (id, org_id, name, rules) VALUES ($1,$2,'legacy',$3)`,
			policyID, org, rules)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM policies WHERE id = $1`, policyID)
			return err
		})
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	var out strings.Builder
	if code := runPolicyCheck(ctx, ownerURL, &out); code != 1 {
		t.Errorf("exit code = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), policyID.String()) || !strings.Contains(out.String(), "topic.categories") {
		t.Errorf("legacy policy not listed:\n%s", out.String())
	}

	// The application role sees no org without app.org_id, so it must not pass.
	out.Reset()
	if code := runPolicyCheck(ctx, appURL, &out); code != 2 {
		t.Errorf("app role: exit code = %d, want 2\n%s", code, out.String())
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
