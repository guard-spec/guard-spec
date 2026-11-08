// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Retried refusals. A client that gets a 400 for a prompt injection may send
// the same request again: Claude Code sends a refused request six times, its
// bodies differing slightly. Each would be one more audit row and one more
// alert event for the same attempt. refusalDedupe folds them: a refusal whose
// key matches one seen within the window (AUDIT_DEDUPE_WINDOW, default 10 s)
// adds to the first row's repeat_count instead of writing a row, and sends no
// event; the first refusal's row and event are written as before.
//
// The key is the org, the API key (its hash), the action, the layer that
// refused the request, the injection label, the policy rule and a hash of
// the text that triggered the refusal (the classified user turn, or the
// untrusted part that scored highest), not of the whole body. Only refusals
// made before the upstream is called (actionBlock with a detection layer) are
// folded; allowed, routed and redacted requests, upstream errors and output
// guard blocks always get a row of their own.
//
// The window slides: each repeat extends it, up to maxRefusalSpan after the
// first refusal, when a new row starts. The state is in this process: with
// several gateway replicas behind a load balancer, retries that land on
// another replica start a row there.

// maxRefusalSpan bounds how long one row collects repeats, so that a client
// that keeps resending a refused request still shows up as new rows.
const maxRefusalSpan = 5 * time.Minute

// maxRefusalRecords bounds the refusals tracked at once; past it, refusals
// get rows of their own.
const maxRefusalRecords = 10000

// defaultAuditDedupeWindow is AUDIT_DEDUPE_WINDOW when it is not set.
const defaultAuditDedupeWindow = 10 * time.Second

type refusalDedupe struct {
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	records map[string]*refusalRecord
}

// refusalRecord is one refusal and its repeats.
type refusalRecord struct {
	id          uuid.UUID // the first row
	first, last time.Time // guarded by refusalDedupe.mu
	count       atomic.Int64

	// mu orders the first row's insert and the updates of its count; state
	// is what became of the insert.
	mu    sync.Mutex
	state refusalState
}

type refusalState int

const (
	refusalPending refusalState = iota
	refusalWritten
	refusalFailed
)

// newRefusalDedupe returns a dedupe of the given window; nil when it is 0 (off).
func newRefusalDedupe(window time.Duration) *refusalDedupe {
	if window <= 0 {
		return nil
	}
	return &refusalDedupe{window: window, now: time.Now, records: map[string]*refusalRecord{}}
}

// refusalKey is the dedupe key of a request; "" when it is not folded.
func refusalKey(e *requestEntry) string {
	if e.Action != actionBlock || e.Detected == "" || e.Trigger == "" || e.OrgID == uuid.Nil {
		return ""
	}
	return cacheKey(e.OrgID, "refusal", e.KeyHash, e.Action, e.Detected, e.Scores.Injection.Label,
		e.RuleID.String(), e.Trigger)
}

// track records e. It returns the record e belongs to, nil when e is not
// folded, and whether e is its first refusal, which writes the row.
func (d *refusalDedupe) track(e *requestEntry) (*refusalRecord, bool) {
	if d == nil {
		return nil, false
	}
	key := refusalKey(e)
	if key == "" {
		return nil, false
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if r, ok := d.records[key]; ok && now.Sub(r.last) <= d.window && now.Sub(r.first) < maxRefusalSpan {
		r.last = now
		r.count.Add(1)
		return r, false
	}
	if len(d.records) >= maxRefusalRecords {
		d.sweep(now)
		if len(d.records) >= maxRefusalRecords {
			return nil, false
		}
	}
	r := &refusalRecord{id: e.ID, first: now, last: now}
	r.count.Store(1)
	d.records[key] = r
	return r, true
}

// sweep drops the records whose window has passed. d.mu is held.
func (d *refusalDedupe) sweep(now time.Time) {
	for k, r := range d.records {
		if now.Sub(r.last) > d.window || now.Sub(r.first) >= maxRefusalSpan {
			delete(d.records, k)
		}
	}
}

// len is the number of records held. Tests use it.
func (d *refusalDedupe) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.records)
}

// auditStore writes audit rows and alert events.
type auditStore struct {
	insert func(requestEntry) error
	// update raises the repeat_count of an org's row to count.
	update func(org, id uuid.UUID, count int64) error
	emit   func(requestEntry)
}

// write writes e's row and events, or folds a repeated refusal into the
// first one's row. The first row reads the count when it is written, so a
// repeat that is handled before it is counted there; a repeat handled after
// it updates the row. When the first row could not be written, a repeat
// writes a row of its own.
func (s auditStore) write(e requestEntry) {
	r := e.repeat
	switch {
	case r == nil:
	case e.repeatFirst:
		r.mu.Lock()
		e.RepeatCount = r.count.Load()
		err := s.insert(e)
		if err != nil {
			r.state = refusalFailed
		} else {
			r.state = refusalWritten
		}
		r.mu.Unlock()
		if err != nil {
			slog.Warn("request log write failed", "err", err, "action", e.Action)
		}
		s.emit(e)
		return
	default:
		r.mu.Lock()
		state := r.state
		if state == refusalWritten {
			if err := s.update(e.OrgID, r.id, r.count.Load()); err != nil {
				slog.Warn("request log repeat count update failed", "err", err)
			}
		}
		r.mu.Unlock()
		if state != refusalFailed {
			return // counted in the first row; its event was sent
		}
		e.repeat = nil
	}
	if err := s.insert(e); err != nil {
		slog.Warn("request log write failed", "err", err, "action", e.Action)
	}
	s.emit(e)
}

// dbAuditStore writes to the requests table and the alert emitter.
func dbAuditStore(db *pgxpool.Pool, content auditContent, emitter *events.Emitter, flagAt float64) auditStore {
	return auditStore{
		insert: func(e requestEntry) error { return insertRequest(db, content, e) },
		update: func(org, id uuid.UUID, count int64) error { return updateRepeatCount(db, org, id, count) },
		emit:   func(e requestEntry) { emitEvents(emitter, e, flagAt) },
	}
}

// updateRepeatCount raises a row's repeat_count to count; it never lowers it,
// so updates that arrive out of order keep the highest.
func updateRepeatCount(db *pgxpool.Pool, org, id uuid.UUID, count int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE requests SET repeat_count = GREATEST(COALESCE(repeat_count, 1), $2) WHERE id = $1`, id, count)
		if err == nil && tag.RowsAffected() == 0 {
			err = errors.New("row not found")
		}
		return err
	})
}

// parseDedupeWindow reads AUDIT_DEDUPE_WINDOW: a duration from 0 (off) to
// maxRefusalSpan.
func parseDedupeWindow(v string) (time.Duration, error) {
	if v == "" {
		return defaultAuditDedupeWindow, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || d > maxRefusalSpan {
		return 0, fmt.Errorf("AUDIT_DEDUPE_WINDOW must be a duration from 0 (off) to %s", maxRefusalSpan)
	}
	return d, nil
}
