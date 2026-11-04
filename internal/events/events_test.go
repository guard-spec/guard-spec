// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/google/uuid"
	dto "github.com/prometheus/client_model/go"
)

func TestEmitterBatchesAndFlushes(t *testing.T) {
	var mu sync.Mutex
	var batches [][]Event
	e := New(nil, Config{Source: "test_batch", Batch: 3, FlushEvery: 50 * time.Millisecond,
		Write: func(_ context.Context, b []Event) error {
			mu.Lock()
			defer mu.Unlock()
			batches = append(batches, append([]Event(nil), b...))
			return nil
		}})
	org := uuid.New()
	for i := 0; i < 4; i++ {
		if !e.Emit(Event{OrgID: org, Type: DetectionBlocked}) {
			t.Fatal("dropped")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := 0
		for _, b := range batches {
			n += len(b)
		}
		mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d events written", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(batches[0]) != 3 {
		t.Fatalf("first batch %d events, want 3 (batch size)", len(batches[0]))
	}
	ev := batches[0][0]
	mu.Unlock()
	if ev.ID == uuid.Nil || ev.OccurredAt.IsZero() || ev.Severity != Info {
		t.Fatalf("defaults not filled: %+v", ev)
	}
	e.Close(context.Background())
	if e.Emit(Event{OrgID: org, Type: DetectionBlocked}) {
		t.Fatal("emit after close accepted")
	}
}

func dropCount() float64 {
	var m dto.Metric
	_ = metrics.EventsDropped.WithLabelValues("test_full").Write(&m)
	return m.GetCounter().GetValue()
}

func TestEmitterDropsWhenFull(t *testing.T) {
	block := make(chan struct{})
	e := New(nil, Config{Source: "test_full", Buffer: 2, Batch: 1, FlushEvery: time.Hour,
		Write: func(context.Context, []Event) error { <-block; return nil }})
	org := uuid.New()
	before := dropCount()
	accepted := 0
	start := time.Now()
	for i := 0; i < 50; i++ {
		if e.Emit(Event{OrgID: org, Type: DetectionBlocked}) {
			accepted++
		}
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Emit blocked")
	}
	dropped := dropCount() - before
	if accepted > 3 || dropped != float64(50-accepted) {
		t.Fatalf("accepted %d, dropped %v", accepted, dropped)
	}
	close(block)
	e.Close(context.Background())
}

func TestNilEmitter(t *testing.T) {
	var e *Emitter
	if e.Emit(Event{OrgID: uuid.New(), Type: DetectionBlocked}) {
		t.Fatal("nil emitter accepted")
	}
	e.Close(context.Background())
}

// BenchmarkEmit is the cost the gateway pays per event on the request path.
func BenchmarkEmit(b *testing.B) {
	e := New(nil, Config{Source: "bench", Buffer: 1 << 16,
		Write: func(context.Context, []Event) error { return nil }})
	defer e.Close(context.Background())
	org := uuid.New()
	attrs := map[string]any{"score": 0.97, "categories": []string{"jailbreak"}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Emit(Event{OrgID: org, Type: DetectionBlocked, Attrs: attrs})
		}
	})
}
