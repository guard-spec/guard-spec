// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits of the in-app stream.
const (
	MaxStreamsPerUser = 5
	MaxStreams        = 2000
	// maxReadIDs is the most ids a read signal carries through NOTIFY
	// (whose payload is limited to 8000 bytes); more send a plain refresh.
	maxReadIDs = 150
)

// ErrTooManyStreams refuses a stream over the limits.
var ErrTooManyStreams = errors.New("too many notification streams")

// ReadEvent says which notifications were marked read.
type ReadEvent struct {
	IDs []uuid.UUID `json:"ids,omitempty"`
	All bool        `json:"all,omitempty"`
}

// Signal is what a stream receives: new notifications (Read nil), or
// notifications marked read. A read of too many ids to list has Refresh set.
type Signal struct {
	Read    *ReadEvent
	Refresh bool
}

// Hub fans NOTIFY guardspec_notifications out to a user's open SSE streams,
// across replicas. The payload is "<user id>" for new notifications,
// "<user id> read all", "<user id> read <id>,<id>" or "<user id> read".
type Hub struct {
	mu    sync.Mutex
	subs  map[uuid.UUID]map[chan Signal]bool
	total int
}

// NewHub returns an empty hub; Run feeds it.
func NewHub() *Hub { return &Hub{subs: map[uuid.UUID]map[chan Signal]bool{}} }

// Run listens until ctx ends.
func (h *Hub) Run(ctx context.Context, db *pgxpool.Pool) {
	Listen(ctx, db, []string{NotificationsChannel}, func(_, payload string) {
		user, sig, ok := ParseSignal(payload)
		if ok {
			h.Publish(user, sig)
		}
	})
}

// ParseSignal reads a NOTIFY payload.
func ParseSignal(payload string) (uuid.UUID, Signal, bool) {
	f := strings.Fields(payload)
	if len(f) == 0 {
		return uuid.Nil, Signal{}, false
	}
	user, err := uuid.Parse(f[0])
	if err != nil {
		return uuid.Nil, Signal{}, false
	}
	if len(f) == 1 {
		return user, Signal{}, true
	}
	if f[1] != "read" {
		return uuid.Nil, Signal{}, false
	}
	switch {
	case len(f) == 2:
		return user, Signal{Refresh: true}, true
	case f[2] == "all":
		return user, Signal{Read: &ReadEvent{All: true}}, true
	}
	ev := &ReadEvent{}
	for _, s := range strings.Split(f[2], ",") {
		id, err := uuid.Parse(s)
		if err != nil {
			return user, Signal{Refresh: true}, true
		}
		ev.IDs = append(ev.IDs, id)
	}
	return user, Signal{Read: ev}, true
}

// ReadPayload builds the NOTIFY payload of a read.
func ReadPayload(user uuid.UUID, ids []uuid.UUID, all bool) string {
	switch {
	case all:
		return user.String() + " read all"
	case len(ids) == 0 || len(ids) > maxReadIDs:
		return user.String() + " read"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.String()
	}
	return user.String() + " read " + strings.Join(parts, ",")
}

// NotifyRead sends a read signal to the user's streams on every replica.
func NotifyRead(ctx context.Context, tx pgx.Tx, user uuid.UUID, ids []uuid.UUID, all bool) error {
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, NotificationsChannel, ReadPayload(user, ids, all))
	return err
}

// Subscribe returns the channel of a user's signals and the function that
// ends the subscription.
func (h *Hub) Subscribe(user uuid.UUID) (<-chan Signal, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= MaxStreams || len(h.subs[user]) >= MaxStreamsPerUser {
		return nil, nil, ErrTooManyStreams
	}
	ch := make(chan Signal, 16)
	if h.subs[user] == nil {
		h.subs[user] = map[chan Signal]bool{}
	}
	h.subs[user][ch] = true
	h.total++
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			delete(h.subs[user], ch)
			if len(h.subs[user]) == 0 {
				delete(h.subs, user)
			}
			h.total--
		})
	}, nil
}

// Publish signals user's streams without blocking. A stream too slow to take
// it misses the signal; the next one refreshes its unread count.
func (h *Hub) Publish(user uuid.UUID, s Signal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[user] {
		select {
		case ch <- s:
		default:
		}
	}
}
