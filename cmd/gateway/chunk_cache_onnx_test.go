//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/guard-spec/guard-spec/internal/metrics"
)

// chunkCacheFor is the scan cache with its chunk layer, in front of the
// Redis at CHUNK_CACHE_REDIS_URL when set (else this process only).
func chunkCacheFor(t *testing.T) *scanCache {
	t.Helper()
	c := newScanCache(defaultScanCacheSize, scanCacheTTL)
	c.chunks = newScanCache(defaultScanCacheSize*chunkCacheFactor, scanCacheTTL)
	if url := os.Getenv("CHUNK_CACHE_REDIS_URL"); url != "" {
		store, err := newRedisStore(url, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.close() })
		for _, x := range []*scanCache{c, c.chunks} {
			x.shared, x.timeout, x.identity = store, 2*time.Second, fixedIdentity("chunk-bench-"+t.Name())
		}
	}
	return c
}

func windowCount(result string) float64 {
	var m dto.Metric
	if err := metrics.ScanWindows.WithLabelValues(result).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// chatLoop is a chat completions conversation that starts with a pasted
// document and grows by one question and answer per turn.
func chatLoop(doc string, turns int) string {
	var b strings.Builder
	b.WriteString(`{"model":"m","messages":[{"role":"user","content":` + jsonQuote(doc) + `}`)
	for i := range turns {
		fmt.Fprintf(&b, `,{"role":"assistant","content":"Answer %d."},{"role":"user","content":%s}`, i,
			jsonQuote(fmt.Sprintf("Question %d: what does section %d of the report say about region %d?", i, i*3, i%17)))
	}
	b.WriteString("]}")
	return b.String()
}

// A chat loop over a ~200k-token document with the real models: from the
// second turn the document's windows come from the scan cache (at least 95%
// of the windows), and a turn costs at most a twentieth of the first at the
// median: only the windows that changed are scored. With
// CHUNK_CACHE_REDIS_URL, a second replica with an empty in-process cache
// reads them from Redis too.
//
//	CHUNK_CACHE_REDIS_URL=redis://localhost:6379/0 L2_MODEL_DIR=... \
//	  go test -tags onnx ./cmd/gateway -run ChunkCacheChatLoop -v
func TestChunkCacheChatLoopWithModels(t *testing.T) {
	runner := liveRunner(t)
	up := newFakeUpstream(t, okUpstream)
	replica := func() *harness {
		return largeGateway(t, up.URL, 300_000, laneConfig(defaultLargeConcurrency()), func(gw *gateway) {
			gw.runner = runner
			gw.cache = chunkCacheFor(t)
		})
	}
	h := replica()
	doc := benignDoc(800_000)
	tokens, err := runner.CountTokens(doc)
	if err != nil {
		t.Fatal(err)
	}
	const turns = 12
	var cold time.Duration
	var warm []time.Duration
	var scored, cached float64
	for turn := range turns {
		s0, c0 := windowCount("scored"), windowCount("cached")
		start := time.Now()
		resp, got := h.post(t, "/v1/chat/completions", chatLoop(doc, turn), nil)
		took := time.Since(start)
		if resp.StatusCode != 200 {
			t.Fatalf("turn %d: %d %.200s", turn, resp.StatusCode, got)
		}
		ds, dc := windowCount("scored")-s0, windowCount("cached")-c0
		t.Logf("turn %2d: %8.1f ms, windows scored %5.0f, cached %5.0f", turn, float64(took.Microseconds())/1000, ds, dc)
		if turn == 0 {
			cold = took
		} else {
			warm = append(warm, took)
			scored, cached = scored+ds, cached+dc
		}
	}
	slices.Sort(warm)
	p50 := warm[len(warm)/2]
	ratio := cached / (cached + scored)
	t.Logf("document %d tokens; warm turns: p50 %v, max %v; %.1f%% of windows cached", tokens, p50, warm[len(warm)-1], 100*ratio)
	// A new turn changes the text's last window, which is scored (about
	// 50 ms on one ONNX thread); everything before it comes from the cache.
	if ratio < 0.95 || p50 > cold/20 {
		t.Errorf("warm turns: %.1f%% cached, p50 %v (first turn %v); want ≥ 95%% and ≤ 1/20 of the first", 100*ratio, p50, cold)
	}

	if os.Getenv("CHUNK_CACHE_REDIS_URL") == "" {
		return
	}
	b := replica() // another replica: empty in-process layer, same Redis
	s0, c0 := windowCount("scored"), windowCount("cached")
	start := time.Now()
	if resp, got := b.post(t, "/v1/chat/completions", chatLoop(doc, turns), nil); resp.StatusCode != 200 {
		t.Fatalf("replica b: %d %.200s", resp.StatusCode, got)
	}
	ds, dc := windowCount("scored")-s0, windowCount("cached")-c0
	t.Logf("replica b, first request: %v, windows scored %.0f, cached %.0f", time.Since(start), ds, dc)
	if dc/(dc+ds) < 0.95 {
		t.Errorf("replica b read %.0f of %.0f windows from Redis", dc, dc+ds)
	}
}
