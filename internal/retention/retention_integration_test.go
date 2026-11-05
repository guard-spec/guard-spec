//go:build integration

package retention

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack. Connects as the application role. The rows are
// dated in 2000 and the run's clock is set just after them, so the test never
// touches other audit rows in a shared database.
func TestRetentionDeletesOldRowsOfEveryOrg(t *testing.T) {
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

	base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	orgs := []uuid.UUID{uuid.New(), uuid.New()}
	for _, org := range orgs {
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'r',$2)`,
				org, org.String()); err != nil {
				return err
			}
			// 5 old rows (day 0) and 1 recent row (day 40) per org.
			for i := 0; i < 6; i++ {
				at := base.Add(time.Duration(i) * time.Minute)
				if i == 5 {
					at = base.AddDate(0, 0, 40)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO requests (org_id, action, created_at) VALUES ($1,'allow',$2)`,
					org, at); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	count := func(org uuid.UUID) int {
		var n int
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM requests WHERE org_id = $1`, org).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	cfg := Config{Days: 30, Batch: 3}
	now := base.AddDate(0, 0, 31) // cutoff: day 1

	// Another replica holds the lock: this one skips.
	holder, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		t.Fatal(err)
	}
	res, err := Once(ctx, db, cfg, now)
	if err != nil || !res.Skipped {
		t.Fatalf("with the lock held elsewhere: %+v %v, want skipped", res, err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
		t.Fatal(err)
	}
	holder.Release()

	res, err = Once(ctx, db, cfg, now)
	if err != nil || res.Skipped {
		t.Fatalf("run: %+v %v", res, err)
	}
	if res.Deleted < 10 {
		t.Errorf("deleted %d, want at least the 10 old rows", res.Deleted)
	}
	for _, org := range orgs {
		if n := count(org); n != 1 {
			t.Errorf("org %s keeps %d rows, want only the recent one", org, n)
		}
	}

	// The lock was released: a second run is not skipped.
	if res, err := Once(ctx, db, cfg, now); err != nil || res.Skipped || res.Deleted != 0 {
		t.Errorf("second run: %+v %v", res, err)
	}

	// Days == 0 keeps everything.
	if res, err := Once(ctx, db, Config{Days: 0, Batch: 3}, now.AddDate(10, 0, 0)); err != nil || res.Deleted != 0 {
		t.Errorf("keep forever: %+v %v", res, err)
	}
}
