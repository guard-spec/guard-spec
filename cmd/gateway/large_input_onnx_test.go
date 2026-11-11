//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// liveRunner loads the model layers behind ml.Live, as the gateway does, with
// one ONNX thread per run (the production compose setting).
func liveRunner(t testing.TB) *inference.Runner {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if onnx.LibraryPath() == "" {
		for _, ext := range []string{"so", "dylib"} {
			if p := filepath.Join(root, ".onnx", "lib", "libonnxruntime."+ext); fileExists(p) {
				t.Setenv(onnx.EnvLibraryPath, p)
			}
		}
	}
	models := os.Getenv(ml.EnvModelDir)
	if models == "" {
		models = filepath.Join(root, "models")
	}
	if onnx.LibraryPath() == "" || ml.DefaultL2Dir(models) == "" {
		t.Skip("models or libonnxruntime absent; see models/manifest.yaml and `make onnx-deps`")
	}
	t.Setenv(onnx.EnvIntraOpThreads, "1")
	s, err := ml.Build(context.Background(), ml.Config{ModelDir: models, Layers: [3]bool{true, true, true}, Fusion: "logreg"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Degraded() {
		t.Skipf("models incomplete: %v", s.Problems)
	}
	live := ml.NewLive(s)
	t.Cleanup(func() { _ = live.Close() })
	return inference.NewRunnerWith(inference.FusedBackend{F: live})
}

// A ~200k-token prompt goes through the gateway with the real models: benign
// it is forwarded, with a payload at its very end it is blocked.
func TestLargeInputWithModels(t *testing.T) {
	runner := liveRunner(t)
	up := newFakeUpstream(t, okUpstream)
	h := largeGateway(t, up.URL, 300_000, laneConfig(defaultLargeConcurrency()), func(gw *gateway) { gw.runner = runner })
	doc := benignDoc(800_000)
	n, err := runner.CountTokens(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		text   string
		status int
	}{{"benign", doc, 200}, {"payload at the end", doc + " " + largeAttack, 400}} {
		start := time.Now()
		resp, got := h.post(t, "/v1/chat/completions", largeChat(tc.text), nil)
		t.Logf("%s, %d tokens: %d in %v", tc.name, n, resp.StatusCode, time.Since(start).Round(time.Millisecond))
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %d %.300s", tc.name, resp.StatusCode, got)
		}
	}
	if up.hits.Load() != 1 {
		t.Fatalf("upstream hits %d, want 1", up.hits.Load())
	}
	if n < 150_000 {
		t.Fatalf("only %d tokens", n)
	}
}

// Load test with the real models: short requests' latency while large
// requests fill the lane, against the same short requests on an idle gateway.
// Local and indicative; the bound only catches short requests queueing
// behind large ones (seconds), not CPU sharing (milliseconds).
func TestShortLatencyUnderLargeLoadWithModels(t *testing.T) {
	runner := liveRunner(t)
	up := newFakeUpstream(t, okUpstream)
	lane := laneConfig(defaultLargeConcurrency())
	lane.QueueTimeout = 10 * time.Minute // the race detector slows the large scans down
	h := largeGateway(t, up.URL, 1_000_000, lane, func(gw *gateway) { gw.runner = runner })
	short := func(n int) []time.Duration {
		var mu sync.Mutex
		var out []time.Duration
		var wg sync.WaitGroup
		for w := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range n / 4 {
					start := time.Now()
					body := largeChat(fmt.Sprintf("Question %d-%d: what is a good recipe for banana bread with walnuts?", w, i))
					if resp, got := h.post(t, "/v1/chat/completions", body, nil); resp.StatusCode != 200 {
						t.Errorf("short: %d %s", resp.StatusCode, got)
					}
					mu.Lock()
					out = append(out, time.Since(start))
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		slices.Sort(out)
		return out
	}
	short(8) // warm up
	idle := short(80)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := range defaultLargeConcurrency() + 1 { // one more than the lane takes: it queues
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, got := h.post(t, "/v1/chat/completions", largeChat(benignDoc(150_000)+fmt.Sprint(i)), nil)
			if resp.StatusCode != 200 {
				t.Errorf("large: %d %.200s", resp.StatusCode, got)
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()
	waitFor(t, func() bool { h.gw.large.mu.Lock(); defer h.gw.large.mu.Unlock(); return h.gw.large.running > 0 })
	busy := short(80)
	overlap := true
	select {
	case <-done:
		overlap = false
	default:
	}
	<-done
	p := func(d []time.Duration, q int) time.Duration { return d[len(d)*q/100].Round(100 * time.Microsecond) }
	t.Logf("%d CPUs, lane %d: short idle p50 %v p99 %v; while large requests run p50 %v p99 %v",
		runtime.NumCPU(), defaultLargeConcurrency(), p(idle, 50), p(idle, 99), p(busy, 50), p(busy, 99))
	if !overlap {
		t.Fatal("the large requests finished before the short ones")
	}
	if p(busy, 99) > 3*p(idle, 99)+250*time.Millisecond {
		t.Fatalf("short requests queued behind large ones: p99 %v, idle %v", p(busy, 99), p(idle, 99))
	}

}
