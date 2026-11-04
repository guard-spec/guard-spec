// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits of the in-app stream.
const (
	MaxStreamsPerUser = 5
	MaxStreams        = 2000
)

// ErrTooManyStreams refuses a stream over the limits.
var ErrTooManyStreams = errors.New("too many notification streams")

// Hub fans NOTIFY guardspec_notifications (a user id) out to that user's
// open SSE streams, across replicas.
type Hub struct {
	mu    sync.Mutex
	subs  map[uuid.UUID]map[chan struct{}]bool
	total int
}

// NewHub returns an empty hub; Run feeds it.
func NewHub() *Hub { return &Hub{subs: map[uuid.UUID]map[chan struct{}]bool{}} }

// Run listens until ctx ends.
func (h *Hub) Run(ctx context.Context, db *pgxpool.Pool) {
	Listen(ctx, db, []string{NotificationsChannel}, func(_, payload string) {
		if u, err := uuid.Parse(payload); err == nil {
			h.Publish(u)
		}
	})
}

// Subscribe returns a channel that receives a signal when user has new
// notifications, and the function that ends the subscription.
func (h *Hub) Subscribe(user uuid.UUID) (<-chan struct{}, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= MaxStreams || len(h.subs[user]) >= MaxStreamsPerUser {
		return nil, nil, ErrTooManyStreams
	}
	ch := make(chan struct{}, 1)
	if h.subs[user] == nil {
		h.subs[user] = map[chan struct{}]bool{}
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

// Publish signals user's streams without blocking.
func (h *Hub) Publish(user uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[user] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
