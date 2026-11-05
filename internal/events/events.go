// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package events carries alert events from the gateway and the control plane
// to the alert worker (docs/alerts.md).
//
// Emit never blocks: an event goes into a bounded in-process buffer, or is
// dropped and counted in guardspec_events_dropped_total{source} when the
// buffer is full. A writer goroutine drains the buffer in batches (100 events
// or 200 ms, whichever comes first), inserts them into the events table, one
// transaction per org under row-level security, and sends
// NOTIFY guardspec_events '<org_id>' so the worker wakes up.
//
// Events hold metadata only: ids, categories, scores, decisions. Never put
// prompt or response text in Attrs.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Channel is the LISTEN/NOTIFY channel; the payload is the org id.
const Channel = "guardspec_events"

// Severities of events and alerts, lowest first.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Event types (docs/alerts.md §1).
const (
	DetectionBlocked     = "detection.blocked"
	DetectionFlagged     = "detection.flagged"
	UpstreamError        = "upstream.error"
	SecurityLoginFailed  = "security.login_failed"
	SecurityMFALocked    = "security.mfa_locked"
	SecurityRoleChanged  = "security.role_changed"
	SecurityOwnerAdded   = "security.owner_added"
	SecuritySSOChanged   = "security.sso_changed"
	ConfigPolicyChanged  = "config.policy_changed"
	ConfigUpstreamChange = "config.upstream_changed"
	AlertTest            = "alert.test"
)

// Types lists the event types of the contract, for validation and the UI.
var Types = []string{DetectionBlocked, DetectionFlagged, UpstreamError, SecurityLoginFailed, SecurityMFALocked,
	SecurityRoleChanged, SecurityOwnerAdded, SecuritySSOChanged, ConfigPolicyChanged, ConfigUpstreamChange, AlertTest}

// Event is one row of the events table.
type Event struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	ProjectID  *uuid.UUID
	Type       string
	Severity   string
	OccurredAt time.Time
	Attrs      map[string]any
}

// Defaults of Config.
const (
	DefaultBuffer     = 4096
	DefaultBatch      = 100
	DefaultFlushEvery = 200 * time.Millisecond
)

// Config tunes an Emitter. Zero values take the defaults.
type Config struct {
	Source     string // metric label: gateway or control_plane
	Buffer     int
	Batch      int
	FlushEvery time.Duration
	// Write stores a batch; nil writes to DB. Tests replace it.
	Write func(ctx context.Context, batch []Event) error
}

// Emitter buffers events and writes them in the background. A nil *Emitter
// accepts and discards events, so callers need no checks.
type Emitter struct {
	cfg   Config
	ch    chan Event
	done  chan struct{}
	once  sync.Once
	mu    sync.RWMutex
	close bool
}

// New starts an emitter that writes to db (or cfg.Write). Stop it with Close.
func New(db *pgxpool.Pool, cfg Config) *Emitter {
	if cfg.Buffer <= 0 {
		cfg.Buffer = DefaultBuffer
	}
	if cfg.Batch <= 0 {
		cfg.Batch = DefaultBatch
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = DefaultFlushEvery
	}
	if cfg.Source == "" {
		cfg.Source = "unknown"
	}
	if cfg.Write == nil {
		cfg.Write = DBWriter(db)
	}
	e := &Emitter{cfg: cfg, ch: make(chan Event, cfg.Buffer), done: make(chan struct{})}
	go e.run()
	return e
}

// Emit queues ev without blocking. It fills in the id, time and severity
// when they are zero. It reports false when the event was dropped.
func (e *Emitter) Emit(ev Event) bool {
	if e == nil {
		return false
	}
	if ev.OrgID == uuid.Nil || ev.Type == "" {
		return false
	}
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now()
	}
	if ev.Severity == "" {
		ev.Severity = Info
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.close {
		metrics.EventsDropped.WithLabelValues(e.cfg.Source).Inc()
		return false
	}
	select {
	case e.ch <- ev:
		return true
	default:
		metrics.EventsDropped.WithLabelValues(e.cfg.Source).Inc()
		return false
	}
}

// Close stops accepting events, writes those buffered and returns when done
// or when ctx ends.
func (e *Emitter) Close(ctx context.Context) {
	if e == nil {
		return
	}
	e.once.Do(func() {
		e.mu.Lock()
		e.close = true
		close(e.ch)
		e.mu.Unlock()
	})
	select {
	case <-e.done:
	case <-ctx.Done():
	}
}

func (e *Emitter) run() {
	defer close(e.done)
	batch := make([]Event, 0, e.cfg.Batch)
	timer := time.NewTimer(e.cfg.FlushEvery)
	defer timer.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := e.cfg.Write(ctx, batch)
		cancel()
		if err != nil {
			slog.Warn("event batch write failed; events dropped", "source", e.cfg.Source, "events", len(batch), "err", err)
			metrics.EventsDropped.WithLabelValues(e.cfg.Source).Add(float64(len(batch)))
		} else {
			metrics.EventsWritten.WithLabelValues(e.cfg.Source).Add(float64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev, ok := <-e.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= e.cfg.Batch {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(e.cfg.FlushEvery)
			}
		case <-timer.C:
			flush()
			timer.Reset(e.cfg.FlushEvery)
		}
	}
}

// DBWriter inserts a batch, one transaction per org with app.org_id set, and
// notifies the worker once per org.
func DBWriter(db *pgxpool.Pool) func(ctx context.Context, batch []Event) error {
	return func(ctx context.Context, batch []Event) error {
		byOrg := map[uuid.UUID][]Event{}
		var order []uuid.UUID
		for _, ev := range batch {
			if _, ok := byOrg[ev.OrgID]; !ok {
				order = append(order, ev.OrgID)
			}
			byOrg[ev.OrgID] = append(byOrg[ev.OrgID], ev)
		}
		var firstErr error
		for _, org := range order {
			if err := Insert(ctx, db, org, byOrg[org]); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

// Insert writes the events of one org and notifies the worker.
func Insert(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, evs []Event) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, org.String()); err != nil {
			return err
		}
		if err := InsertTx(ctx, tx, org, evs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, Channel, org.String())
		return err
	})
}

// InsertTx inserts events of org in tx (app.org_id already set). It does not
// notify.
func InsertTx(ctx context.Context, tx pgx.Tx, org uuid.UUID, evs []Event) error {
	n := len(evs)
	ids := make([]uuid.UUID, n)
	projects := make([]*uuid.UUID, n)
	types := make([]string, n)
	sevs := make([]string, n)
	times := make([]time.Time, n)
	attrs := make([]string, n)
	for i, ev := range evs {
		ids[i], projects[i], types[i], sevs[i], times[i] = ev.ID, ev.ProjectID, ev.Type, ev.Severity, ev.OccurredAt
		a := ev.Attrs
		if a == nil {
			a = map[string]any{}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		attrs[i] = string(raw)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO events (id, org_id, project_id, type, severity, occurred_at, attrs)
		 SELECT u.id, $1, u.project_id, u.type, u.severity::alert_severity, u.occurred_at, u.attrs::jsonb
		 FROM unnest($2::uuid[], $3::uuid[], $4::text[], $5::text[], $6::timestamptz[], $7::text[])
		   AS u(id, project_id, type, severity, occurred_at, attrs)
		 ON CONFLICT (id) DO NOTHING`,
		org, ids, projects, types, sevs, times, attrs)
	return err
}
