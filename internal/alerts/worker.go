// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PollInterval is the safety net under LISTEN.
const PollInterval = 2 * time.Second

// maxConcurrentOrgs bounds the orgs one replica works on at once.
const maxConcurrentOrgs = 8

// Worker runs the engine and the dispatcher: on NOTIFY guardspec_events and
// guardspec_outbox for the org named, and every PollInterval for every org
// with work (alert_work_orgs()).
type Worker struct {
	DB         *pgxpool.Pool
	Engine     *Engine
	Dispatcher *Dispatcher
	Poll       time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
	again   map[uuid.UUID]bool
	sem     chan struct{}
	wg      sync.WaitGroup
}

// Run works until ctx ends, then waits for the orgs in progress.
func (w *Worker) Run(ctx context.Context) {
	w.running, w.again = map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	w.sem = make(chan struct{}, maxConcurrentOrgs)
	poll := w.Poll
	if poll <= 0 {
		poll = PollInterval
	}
	notes := make(chan uuid.UUID, 256)
	go w.listen(ctx, notes)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	w.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return
		case org := <-notes:
			w.kick(ctx, org)
		case <-ticker.C:
			w.pollOnce(ctx)
		}
	}
}

func (w *Worker) pollOnce(ctx context.Context) {
	rows, err := w.DB.Query(ctx, `SELECT org_id FROM alert_work_orgs()`)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("alert worker poll failed", "err", err)
		}
		return
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		slog.Warn("alert worker poll failed", "err", err)
		return
	}
	for _, org := range orgs {
		w.kick(ctx, org)
	}
}

// kick works on org now, or once more after the run in progress.
func (w *Worker) kick(ctx context.Context, org uuid.UUID) {
	w.mu.Lock()
	if w.running[org] {
		w.again[org] = true
		w.mu.Unlock()
		return
	}
	w.running[org] = true
	w.mu.Unlock()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for {
			select {
			case w.sem <- struct{}{}:
			case <-ctx.Done():
				w.done(org)
				return
			}
			w.work(ctx, org)
			<-w.sem
			w.mu.Lock()
			if !w.again[org] || ctx.Err() != nil {
				delete(w.running, org)
				delete(w.again, org)
				w.mu.Unlock()
				return
			}
			delete(w.again, org)
			w.mu.Unlock()
		}
	}()
}

func (w *Worker) done(org uuid.UUID) {
	w.mu.Lock()
	delete(w.running, org)
	delete(w.again, org)
	w.mu.Unlock()
}

// work runs the engine, then delivers what it queued.
func (w *Worker) work(ctx context.Context, org uuid.UUID) {
	if _, err := w.Engine.ProcessOrg(ctx, org); err != nil && ctx.Err() == nil {
		slog.Warn("alert rules failed", "org", org, "err", err)
	}
	if _, err := w.Dispatcher.DispatchOrg(ctx, org); err != nil && ctx.Err() == nil {
		slog.Warn("alert dispatch failed", "org", org, "err", err)
	}
}

// listen forwards NOTIFY payloads (org ids) until ctx ends, reconnecting
// after a failure. While it is down, the poll still runs.
func (w *Worker) listen(ctx context.Context, out chan<- uuid.UUID) {
	Listen(ctx, w.DB, []string{events.Channel, OutboxChannel}, func(_, payload string) {
		if org, err := uuid.Parse(payload); err == nil {
			select {
			case out <- org:
			default: // the poll catches up
			}
		}
	})
}

// Listen holds one connection that LISTENs on chans and calls fn for each
// notification, until ctx ends. It reconnects after errors.
func Listen(ctx context.Context, db *pgxpool.Pool, chans []string, fn func(channel, payload string)) {
	for ctx.Err() == nil {
		err := listenOnce(ctx, db, chans, fn)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("LISTEN connection lost; reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func listenOnce(ctx context.Context, db *pgxpool.Pool, chans []string, fn func(string, string)) error {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// A connection left listening must not go back to the pool.
		_ = conn.Conn().Close(context.Background())
		conn.Release()
	}()
	for _, ch := range chans {
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
			return err
		}
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		fn(n.Channel, n.Payload)
	}
}
