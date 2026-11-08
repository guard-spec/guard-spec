// Package retention deletes rows older than their retention period: audit
// rows (the requests table), the activity log and ended sessions, and
// expired entries of the shared scan cache.
//
// Every control plane replica runs the job; a Postgres advisory lock lets one
// of them work at a time and the others skip that round. Rows go in batches,
// each its own short transaction, so a table is never locked for long.
//
// requests and activity_log are row-level secured and hold rows of every org,
// so their batches go through SECURITY DEFINER functions (purge_audit_rows,
// purge_activity_rows) that the application role may execute; the role
// itself keeps no way around RLS. sessions is keyed by user and not
// row-level secured, so it is deleted directly. scan_cache is row-level
// secured too (purge_scan_cache); its rows expire on their own schedule, so
// they are purged even when every retention period is 0.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LockKey is the advisory lock that serializes runs across replicas.
const LockKey int64 = 0x6775617264726574 // "guardret"

// Config is the retention policy. A period of 0 days keeps those rows
// forever.
type Config struct {
	Days         int           // audit rows (requests)
	ActivityDays int           // activity_log rows
	SessionDays  int           // sessions revoked or expired this long ago
	ScanCache    bool          // expired scan_cache rows (SCAN_CACHE_BACKEND=postgres)
	Interval     time.Duration // time between runs
	Batch        int           // rows per delete
}

func (c Config) enabled() bool {
	return c.Days > 0 || c.ActivityDays > 0 || c.SessionDays > 0 || c.ScanCache
}

// Result of one run.
type Result struct {
	Deleted          int64 // audit rows
	ActivityDeleted  int64
	SessionsDeleted  int64
	ScanCacheDeleted int64 // expired scan cache entries
	DataKeysDeleted  int64 // retired content data keys no row uses any more
	Skipped          bool  // another replica held the lock
}

// The batched deletes. Each returns how many rows it removed.
const (
	purgeAudit    = `SELECT purge_audit_rows($1, $2)`
	purgeActivity = `SELECT purge_activity_rows($1, $2)`
	// Expired scan cache entries; the cutoff is the database's now().
	purgeScanCache = `SELECT purge_scan_cache($1)`
	// Retired data keys of stored content that no row names any more
	// (migration 021): after audit rows go, so do the keys only they used.
	purgeDataKeys = `SELECT purge_unused_data_keys()`
	// An active session has revoked_at NULL and expires_at in the future,
	// so it matches neither condition while the cutoff is in the past.
	purgeSessions = `DELETE FROM sessions WHERE id IN (
		SELECT id FROM sessions WHERE revoked_at < $1 OR expires_at < $1
		LIMIT $2 FOR UPDATE SKIP LOCKED)`
)

// Once runs one retention pass: for each table with a period, it deletes in
// batches every row older than now minus that period, unless another session
// holds LockKey.
func Once(ctx context.Context, db *pgxpool.Pool, cfg Config, now time.Time) (res Result, err error) {
	if !cfg.enabled() {
		return res, nil
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, LockKey).Scan(&locked); err != nil {
		return res, err
	}
	if !locked {
		return Result{Skipped: true}, nil
	}
	defer func() {
		// A session lock outlives the run unless released; a connection that
		// cannot release it is closed, which ends the session and the lock.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, uerr := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, LockKey); uerr != nil {
			slog.Warn("retention unlock failed; closing the connection", "err", uerr)
			_ = conn.Conn().Close(unlockCtx)
		}
	}()

	// purge deletes batches until one comes back short.
	purge := func(name string, days int, count func(cutoff time.Time) (int64, error), total *int64, observe func(int64)) error {
		if days <= 0 {
			return nil
		}
		cutoff := now.AddDate(0, 0, -days)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := count(cutoff)
			if err != nil {
				return fmt.Errorf("purge %s batch: %w", name, err)
			}
			*total += n
			observe(n)
			if n < int64(cfg.Batch) {
				return nil
			}
		}
	}
	viaFunc := func(query string) func(time.Time) (int64, error) {
		return func(cutoff time.Time) (n int64, err error) {
			err = conn.QueryRow(ctx, query, cutoff, cfg.Batch).Scan(&n)
			return n, err
		}
	}
	deleteSessions := func(cutoff time.Time) (int64, error) {
		tag, err := conn.Exec(ctx, purgeSessions, cutoff, cfg.Batch)
		return tag.RowsAffected(), err
	}
	tableDeleted := func(table string) func(int64) {
		return func(n int64) { metrics.RetentionTableDeleted.WithLabelValues(table).Add(float64(n)) }
	}

	if err := purge("audit", cfg.Days, viaFunc(purgeAudit), &res.Deleted,
		func(n int64) { metrics.RetentionDeleted.WithLabelValues().Add(float64(n)) }); err != nil {
		return res, err
	}
	if cfg.Days > 0 {
		var n int64
		if err := conn.QueryRow(ctx, purgeDataKeys).Scan(&n); err != nil {
			return res, fmt.Errorf("purge data keys: %w", err)
		}
		res.DataKeysDeleted = n
		metrics.RetentionTableDeleted.WithLabelValues("org_data_keys").Add(float64(n))
	}
	if err := purge("activity_log", cfg.ActivityDays, viaFunc(purgeActivity), &res.ActivityDeleted,
		tableDeleted("activity_log")); err != nil {
		return res, err
	}
	if err := purge("sessions", cfg.SessionDays, deleteSessions, &res.SessionsDeleted,
		tableDeleted("sessions")); err != nil {
		return res, err
	}
	if cfg.ScanCache {
		// purge's cutoff is not used: an entry carries its own expiry.
		expired := func(time.Time) (n int64, err error) {
			err = conn.QueryRow(ctx, purgeScanCache, cfg.Batch).Scan(&n)
			return n, err
		}
		if err := purge("scan_cache", 1, expired, &res.ScanCacheDeleted, tableDeleted("scan_cache")); err != nil {
			return res, err
		}
	}
	return res, nil
}

// Run calls Once now and then every cfg.Interval until ctx ends.
func Run(ctx context.Context, db *pgxpool.Pool, cfg Config) {
	if !cfg.enabled() {
		slog.Info("retention off: audit rows, the activity log and sessions are kept forever")
		return
	}
	slog.Info("retention", "audit_days", cfg.Days, "activity_days", cfg.ActivityDays,
		"session_days", cfg.SessionDays, "scan_cache", cfg.ScanCache, "interval", cfg.Interval.String(), "batch", cfg.Batch)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		res, err := Once(ctx, db, cfg, time.Now())
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			metrics.RetentionRuns.WithLabelValues("error").Inc()
			slog.Error("retention failed", "err", err, "deleted", res.Deleted,
				"activity_deleted", res.ActivityDeleted, "sessions_deleted", res.SessionsDeleted)
		case res.Skipped:
			metrics.RetentionRuns.WithLabelValues("skipped").Inc()
			slog.Debug("retention skipped: another replica is running it")
		default:
			metrics.RetentionRuns.WithLabelValues("ok").Inc()
			if res.Deleted+res.ActivityDeleted+res.SessionsDeleted+res.ScanCacheDeleted+res.DataKeysDeleted > 0 {
				slog.Info("retention", "deleted", res.Deleted,
					"activity_deleted", res.ActivityDeleted, "sessions_deleted", res.SessionsDeleted,
					"scan_cache_deleted", res.ScanCacheDeleted, "data_keys_deleted", res.DataKeysDeleted)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
