// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/events"
	"github.com/giaplee/guard-spec/internal/inference"
)

func TestEventsForRequests(t *testing.T) {
	failing := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	tests := []struct {
		name     string
		upstream string
		body     string
		want     []string
		layer    string
	}{
		{"injection blocked", "", attackBody, []string{events.DetectionBlocked}, "l1"},
		{"encoding blocked", "", "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\U000E0041\"}]}",
			[]string{events.DetectionBlocked}, layerSanitizer},
		{"clean", "", clean, nil, ""},
		{"upstream 5xx", failing.URL, clean, []string{events.UpstreamError}, ""},
		{"invalid body is not a detection", "", `{"messages":`, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := startGateway(t, tt.upstream, nil)
			h.post(t, "/v1/chat/completions", tt.body, nil)
			row := h.oneRow(t)
			evs := eventsFor(&row, defaultFlagThreshold)
			var types []string
			for _, ev := range evs {
				types = append(types, ev.Type)
				raw, _ := json.Marshal(ev.Attrs)
				for _, secret := range []string{"ignore all previous", "hello", "hi\U000E0041", "messages"} {
					if strings.Contains(string(raw), secret) {
						t.Fatalf("event attrs carry request text: %s", raw)
					}
				}
				if ev.OrgID != devOrg {
					t.Fatalf("org %s", ev.OrgID)
				}
			}
			if !slices.Equal(types, tt.want) {
				t.Fatalf("events %v, want %v", types, tt.want)
			}
			if tt.layer != "" && evs[0].Attrs["layer"] != tt.layer {
				t.Fatalf("layer %v, want %s", evs[0].Attrs["layer"], tt.layer)
			}
			if len(evs) > 0 && evs[0].Type == events.UpstreamError &&
				(evs[0].Attrs["error_kind"] != errorKind5xx || evs[0].Attrs["status"].(int) < 500) {
				t.Fatalf("upstream attrs %v", evs[0].Attrs)
			}
			if len(evs) > 0 && evs[0].Type == events.DetectionBlocked && evs[0].Attrs["request_id"] != row.ID.String() {
				t.Fatalf("request_id %v, row %s", evs[0].Attrs["request_id"], row.ID)
			}
		})
	}
}

func TestFlaggedBelowBlockThreshold(t *testing.T) {
	row := requestEntry{OrgID: devOrg, Action: actionAllow, Model: "m"}
	row.Scores.Injection = inference.Score{Label: "jailbreak", Confidence: 0.6}
	evs := eventsFor(&row, 0.5)
	if len(evs) != 1 || evs[0].Type != events.DetectionFlagged || evs[0].Severity != events.Info {
		t.Fatalf("events %+v", evs)
	}
	if cats := evs[0].Attrs["categories"].([]string); len(cats) != 1 || cats[0] != "jailbreak" {
		t.Fatalf("categories %v", cats)
	}
	row.Scores.Injection.Confidence = 0.4
	if evs := eventsFor(&row, 0.5); len(evs) != 0 {
		t.Fatalf("below the flag threshold: %+v", evs)
	}
}

// BenchmarkGatewayEvents compares gateway request latency with event
// emission off and on (docs/alerts.md: p99 must not rise by more than 1 ms).
// Every request is an attack that is blocked, so every request emits an
// event. It reports p50 and p99 per request.
//
//	go test ./cmd/gateway -run '^$' -bench GatewayEvents -benchtime 3000x
func BenchmarkGatewayEvents(b *testing.B) {
	for _, on := range []bool{false, true} {
		name := "events=off"
		if on {
			name = "events=on"
		}
		b.Run(name, func(b *testing.B) {
			runner, err := inference.NewRunner("")
			if err != nil {
				b.Fatal(err)
			}
			var written atomic.Int64
			var em *events.Emitter
			if on {
				em = events.New(nil, events.Config{Source: "bench", Write: func(_ context.Context, batch []events.Event) error {
					written.Add(int64(len(batch)))
					return nil
				}})
			}
			gw := testGateway(&testing.T{}, runner)
			gw.audit = newAuditLog(func(e requestEntry) { emitEvents(em, e, defaultFlagThreshold) })
			app := newApp(gw, testLookup)
			durations := make([]time.Duration, 0, b.N)
			var mu sync.Mutex
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(attackBody))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("x-api-key", "test")
				start := time.Now()
				resp, err := app.Test(req, -1)
				d := time.Since(start)
				if err != nil {
					b.Fatal(err)
				}
				_ = resp.Body.Close()
				mu.Lock()
				durations = append(durations, d)
				mu.Unlock()
			}
			b.StopTimer()
			gw.audit.wait()
			em.Close(context.Background())
			if on && written.Load() == 0 {
				b.Fatal("no events written")
			}
			slices.Sort(durations)
			pct := func(p float64) float64 {
				return float64(durations[min(len(durations)-1, int(p*float64(len(durations))))].Microseconds())
			}
			b.ReportMetric(pct(0.50), "p50-µs")
			b.ReportMetric(pct(0.99), "p99-µs")
		})
	}
}
