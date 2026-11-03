// Package retention deletes audit rows (the requests table) older than the
// retention period.
//
// Every control plane replica runs the job; a Postgres advisory lock lets one
// of them work at a time and the others skip that round. Rows go in batches,
// each its own short transaction, so the table is never locked for long.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/metrics"
)

// LockKey is the advisory lock that serializes runs across replicas.
const LockKey int64 = 0x6775617264726574 // "guardret"

// Config is the retention policy. Days == 0 keeps rows forever.
type Config struct {
	Days     int
	Interval time.Duration // time between runs
	Batch    int           // rows per delete
}

// Result of one run.
type Result struct {
	Deleted int64
	Skipped bool // another replica held the lock
}

// Once runs one retention pass: it deletes, in batches, every row older than
// now minus cfg.Days, unless another session holds LockKey.
func Once(ctx context.Context, db *pgxpool.Pool, cfg Config, now time.Time) (res Result, err error) {
	if cfg.Days <= 0 {
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

	cutoff := now.AddDate(0, 0, -cfg.Days)
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var n int64
		if err := conn.QueryRow(ctx, `SELECT purge_audit_rows($1, $2)`, cutoff, cfg.Batch).Scan(&n); err != nil {
			return res, fmt.Errorf("purge batch: %w", err)
		}
		res.Deleted += n
		metrics.RetentionDeleted.WithLabelValues().Add(float64(n))
		if n < int64(cfg.Batch) {
			return res, nil
		}
	}
}

// Run calls Once now and then every cfg.Interval until ctx ends.
func Run(ctx context.Context, db *pgxpool.Pool, cfg Config) {
	if cfg.Days <= 0 {
		slog.Info("audit retention off: rows are kept forever")
		return
	}
	slog.Info("audit retention", "days", cfg.Days, "interval", cfg.Interval.String(), "batch", cfg.Batch)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		res, err := Once(ctx, db, cfg, time.Now())
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			metrics.RetentionRuns.WithLabelValues("error").Inc()
			slog.Error("audit retention failed", "err", err, "deleted", res.Deleted)
		case res.Skipped:
			metrics.RetentionRuns.WithLabelValues("skipped").Inc()
			slog.Debug("audit retention skipped: another replica is running it")
		default:
			metrics.RetentionRuns.WithLabelValues("ok").Inc()
			if res.Deleted > 0 {
				slog.Info("audit retention", "deleted", res.Deleted)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
