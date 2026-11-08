// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// Worker settings.
const (
	// Settle: events younger than this wait, so an emitter batch that commits
	// late (its created_at is its transaction's start) is not skipped by a
	// cursor that moved past it.
	Settle   = 10 * time.Second
	Batch    = 200
	lease    = 2 * time.Minute
	maxSinks = 20
	// backoff of the n-th failure in a row: 10 s doubling up to 30 minutes.
	backoffBase = 10 * time.Second
	backoffMax  = 30 * time.Minute
)

// Resolver gives a sink its secret and whether it may reach private
// addresses; the control plane checks ALERTS_SECRET_ORGS and
// ALERTS_PRIVATE_ORGS there.
type Resolver interface {
	Secret(org uuid.UUID, env string) (string, error)
	AllowPrivate(org uuid.UUID, asked bool) bool
}

// Stored is a sink row.
type Stored struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	Kind         string
	Config       map[string]any
	SecretEnv    *string
	EventTypes   []string
	MinSeverity  string
	AllowPrivate bool
	CursorAt     time.Time
	CursorID     uuid.UUID
	Failures     int
}

// Sink builds the delivery settings of a stored sink.
func (st Stored) Sink(r Resolver) (Sink, error) {
	s := Sink{Kind: st.Kind, Config: st.Config, AllowPrivate: r.AllowPrivate(st.OrgID, st.AllowPrivate)}
	if st.SecretEnv != nil && *st.SecretEnv != "" {
		v, err := r.Secret(st.OrgID, *st.SecretEnv)
		if err != nil {
			return s, err
		}
		s.Secret = v
	}
	return s, nil
}

// severityRank orders severities; an event below the sink's minimum is not sent.
var severityRank = map[string]int{events.Info: 0, events.Warning: 1, events.Critical: 2}

// Wanted reports whether ev goes to the sink.
func (st Stored) Wanted(ev events.Event) bool {
	if severityRank[ev.Severity] < severityRank[st.MinSeverity] {
		return false
	}
	if len(st.EventTypes) == 0 {
		return true
	}
	for _, t := range st.EventTypes {
		if ev.Type == t || (strings.HasSuffix(t, ".") && strings.HasPrefix(ev.Type, t)) {
			return true
		}
	}
	return false
}

// Run delivers due sinks every interval until ctx ends.
func Run(ctx context.Context, db *pgxpool.Pool, r Resolver, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := Once(ctx, db, r, time.Now()); err != nil && ctx.Err() == nil {
			slog.Warn("siem export", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Once claims the due sinks and delivers one batch to each. It returns how
// many events it delivered.
func Once(ctx context.Context, db *pgxpool.Pool, r Resolver, now time.Time) (int, error) {
	rows, err := db.Query(ctx, `SELECT org_id, id FROM claim_siem_sinks($1, $2)`, lease, maxSinks)
	if err != nil {
		return 0, err
	}
	type claim struct{ org, id uuid.UUID }
	var claims []claim
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.org, &c.id); err != nil {
			rows.Close()
			return 0, err
		}
		claims = append(claims, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	total := 0
	for _, c := range claims {
		n, err := deliverSink(ctx, db, r, c.org, c.id, now)
		total += n
		if err != nil && ctx.Err() == nil {
			slog.Warn("siem sink delivery failed", "org", c.org, "sink", c.id, "err", err)
		}
	}
	return total, nil
}

// Load reads one sink of org.
func Load(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, org, id uuid.UUID) (Stored, error) {
	var st Stored
	err := q.QueryRow(ctx, `SELECT id, org_id, kind, config, secret_env, event_types, min_severity::text, allow_private,
		cursor_at, cursor_id, failures FROM siem_sinks WHERE org_id = $1 AND id = $2`, org, id).
		Scan(&st.ID, &st.OrgID, &st.Kind, &st.Config, &st.SecretEnv, &st.EventTypes, &st.MinSeverity, &st.AllowPrivate,
			&st.CursorAt, &st.CursorID, &st.Failures)
	return st, err
}

func deliverSink(ctx context.Context, db *pgxpool.Pool, r Resolver, org, id uuid.UUID, now time.Time) (int, error) {
	var st Stored
	var batch []events.Event
	var lastAt time.Time
	var lastID uuid.UUID
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		var err error
		if st, err = Load(ctx, tx, org, id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, project_id, type, severity::text, occurred_at, attrs, created_at
			FROM events WHERE org_id = $1 AND (created_at, id) > ($2, $3) AND created_at < $4
			ORDER BY created_at, id LIMIT $5`, org, st.CursorAt, st.CursorID, now.Add(-Settle), Batch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ev := events.Event{OrgID: org}
			var created time.Time
			if err := rows.Scan(&ev.ID, &ev.ProjectID, &ev.Type, &ev.Severity, &ev.OccurredAt, &ev.Attrs, &created); err != nil {
				return err
			}
			lastAt, lastID = created, ev.ID
			if st.Wanted(ev) {
				batch = append(batch, ev)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	if lastID == uuid.Nil {
		return 0, reschedule(ctx, db, org, id, nil, nil)
	}
	sink, err := st.Sink(r)
	if err == nil {
		dctx, cancel := context.WithTimeout(ctx, Timeout*2)
		err = Deliver(dctx, sink, batch)
		cancel()
	}
	if err != nil {
		return 0, fail(ctx, db, org, id, st.Failures+1, err)
	}
	n := len(batch)
	return n, reschedule(ctx, db, org, id, &cursor{lastAt, lastID}, &n)
}

type cursor struct {
	at time.Time
	id uuid.UUID
}

// reschedule moves the cursor after a delivery and makes the sink due again.
// Scheduling uses the database's clock; now only sets the settle cutoff.
func reschedule(ctx context.Context, db *pgxpool.Pool, org, id uuid.UUID, c *cursor, delivered *int) error {
	return tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		if c == nil {
			_, err := tx.Exec(ctx, `UPDATE siem_sinks SET next_attempt_at = NOW() WHERE org_id = $1 AND id = $2`, org, id)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE siem_sinks SET cursor_at = $3, cursor_id = $4, next_attempt_at = NOW(), failures = 0,
			last_error = NULL, last_success_at = NOW(), delivered = delivered + $5 WHERE org_id = $1 AND id = $2`,
			org, id, c.at, c.id, *delivered)
		return err
	})
}

// fail records a failed delivery and backs off.
func fail(ctx context.Context, db *pgxpool.Pool, org, id uuid.UUID, failures int, cause error) error {
	wait := backoffBase << min(failures-1, 20)
	if wait > backoffMax || wait <= 0 {
		wait = backoffMax
	}
	msg := cause.Error()
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE siem_sinks SET failures = $3, last_error = $4, next_attempt_at = NOW() + $5::interval
			WHERE org_id = $1 AND id = $2`, org, id, failures, msg, wait)
		return err
	})
	return errors.Join(cause, err)
}

// Test sends one synthetic event (alert.test) to a sink and returns the
// error, without touching its cursor.
func Test(ctx context.Context, s Sink, org uuid.UUID, actor string) error {
	ev := events.Event{ID: uuid.New(), OrgID: org, Type: events.AlertTest, Severity: events.Info,
		OccurredAt: time.Now().UTC(), Attrs: map[string]any{"actor_id": actor, "note": "Guard Spec SIEM export test"}}
	ctx, cancel := context.WithTimeout(ctx, Timeout*2)
	defer cancel()
	if err := Deliver(ctx, s, []events.Event{ev}); err != nil {
		return fmt.Errorf("test delivery: %w", err)
	}
	return nil
}
