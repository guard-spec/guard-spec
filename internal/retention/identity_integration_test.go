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

// Requires the compose stack. Connects as the application role, which sees
// activity_log only through RLS. Rows are dated around 2000 and the run's
// clock is set just after them, so the test never touches other rows in a
// shared database; audit retention is off in these runs.
func TestRetentionActivityLogAndSessions(t *testing.T) {
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
	recent := base.AddDate(0, 0, 40)
	far := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	tag := "rf62-" + uuid.NewString() // marks this test's activity rows

	// Activity rows: two orgs and the instance scope (org_id NULL), each
	// with 4 old rows (day 0) and 1 recent row (day 40).
	orgs := []uuid.UUID{uuid.New(), uuid.New()}
	addActivity := func(tx pgx.Tx, org *uuid.UUID) error {
		for i := 0; i < 5; i++ {
			at := base.Add(time.Duration(i) * time.Minute)
			if i == 4 {
				at = recent
			}
			if _, err := tx.Exec(ctx, `INSERT INTO activity_log (org_id, at, action, target) VALUES ($1,$2,'test',$3)`,
				org, at, tag); err != nil {
				return err
			}
		}
		return nil
	}
	for _, org := range orgs {
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'r',$2)`,
				org, org.String()); err != nil {
				return err
			}
			return addActivity(tx, &org)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	instance := func(fn func(pgx.Tx) error) error {
		return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.instance_scope', 'on', true)`); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	if err := instance(func(tx pgx.Tx) error { return addActivity(tx, nil) }); err != nil {
		t.Fatal(err)
	}
	countActivity := func() (perOrg []int, inst int) {
		for _, org := range orgs {
			var n int
			err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE target = $1`, tag).Scan(&n)
			})
			if err != nil {
				t.Fatal(err)
			}
			perOrg = append(perOrg, n)
		}
		err := instance(func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE target = $1 AND org_id IS NULL`, tag).Scan(&inst)
		})
		if err != nil {
			t.Fatal(err)
		}
		return perOrg, inst
	}
	// Without an org or the instance scope, the application role sees none
	// of them: the job does not rely on RLS being loosened.
	var visible int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE target = $1`, tag).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("application role sees %d activity rows outside RLS, want 0", visible)
	}

	// Sessions of one user, all created at day 0.
	var user uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`, tag+"@example.com").Scan(&user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, user) })
	sessions := []struct {
		name     string
		expires  time.Time
		revoked  *time.Time
		wantKept bool
	}{
		{"active (old login, not revoked, expires later)", far, nil, true},
		{"expired long ago", base.Add(time.Hour), nil, false},
		{"revoked long ago, not expired", far, &base, false},
		{"revoked recently", far, &recent, true},
		{"expired recently", recent, nil, true},
		{"expired and revoked long ago", base.Add(time.Hour), &base, false},
	}
	ids := make([]uuid.UUID, len(sessions))
	for i, s := range sessions {
		if err := db.QueryRow(ctx,
			`INSERT INTO sessions (user_id, method, created_at, last_seen_at, expires_at, revoked_at)
			 VALUES ($1,'password',$2,$2,$3,$4) RETURNING id`,
			user, base, s.expires, s.revoked).Scan(&ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	sessionExists := func(id uuid.UUID) bool {
		var ok bool
		if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id = $1)`, id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	now := base.AddDate(0, 0, 31) // cutoff: day 1

	// 0 disables: with every period 0, nothing goes, even far in the future.
	if res, err := Once(ctx, db, Config{Batch: 2}, now.AddDate(50, 0, 0)); err != nil || res != (Result{}) {
		t.Fatalf("all off: %+v %v", res, err)
	}
	// One table off keeps that table: sessions only.
	res, err := Once(ctx, db, Config{SessionDays: 30, Batch: 2}, now)
	if err != nil || res.Skipped || res.ActivityDeleted != 0 || res.Deleted != 0 {
		t.Fatalf("sessions only: %+v %v", res, err)
	}
	if perOrg, inst := countActivity(); perOrg[0] != 5 || perOrg[1] != 5 || inst != 5 {
		t.Fatalf("activity with ACTIVITY_LOG_RETENTION_DAYS=0: %v %d, want every row kept", perOrg, inst)
	}
	if res.SessionsDeleted < 3 {
		t.Errorf("sessions deleted %d, want at least 3", res.SessionsDeleted)
	}
	for i, s := range sessions {
		if got := sessionExists(ids[i]); got != s.wantKept {
			t.Errorf("session %q: kept=%v, want %v", s.name, got, s.wantKept)
		}
	}

	// Another replica holds the lock: this one skips.
	holder, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ActivityDays: 30, SessionDays: 30, Batch: 2}
	if res, err := Once(ctx, db, cfg, now); err != nil || !res.Skipped {
		t.Fatalf("with the lock held elsewhere: %+v %v, want skipped", res, err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
		t.Fatal(err)
	}
	holder.Release()

	// Activity log, in batches of 2: 12 old rows of two orgs and the
	// instance go, the recent ones stay.
	res, err = Once(ctx, db, cfg, now)
	if err != nil || res.Skipped {
		t.Fatalf("run: %+v %v", res, err)
	}
	if res.ActivityDeleted < 12 {
		t.Errorf("activity deleted %d, want at least the 12 old rows", res.ActivityDeleted)
	}
	if perOrg, inst := countActivity(); perOrg[0] != 1 || perOrg[1] != 1 || inst != 1 {
		t.Errorf("activity left %v (orgs) and %d (instance), want only the recent row of each", perOrg, inst)
	}
	for i, s := range sessions {
		if got := sessionExists(ids[i]); got != s.wantKept {
			t.Errorf("session %q after the second run: kept=%v, want %v", s.name, got, s.wantKept)
		}
	}

	// Later, the recent ones are old too; the active session still stays.
	res, err = Once(ctx, db, cfg, recent.AddDate(0, 0, 31))
	if err != nil || res.ActivityDeleted < 3 || res.SessionsDeleted < 2 {
		t.Fatalf("later run: %+v %v", res, err)
	}
	if perOrg, inst := countActivity(); perOrg[0] != 0 || perOrg[1] != 0 || inst != 0 {
		t.Errorf("activity left %v %d, want none", perOrg, inst)
	}
	if !sessionExists(ids[0]) {
		t.Error("the active session was deleted")
	}
	for _, i := range []int{3, 4} {
		if sessionExists(ids[i]) {
			t.Errorf("session %q is still there", sessions[i].name)
		}
	}
}
