// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

func chunkResult(score float64) fusion.Result {
	return fusion.Result{Score: score, Layers: [3]float64{0.2, score, fusion.Missing}, Category: "direct_injection",
		Categories: map[string]float64{"direct_injection": score}, Rules: []string{"r1"}, Floor: 0.1}
}

// A window's entry round-trips through the shared layer, and is found only
// by the same org under the same model identity.
func TestChunkCacheIsolation(t *testing.T) {
	ctx := context.Background()
	store := newFakeShared()
	replica := func(identity string) *scanCache {
		c := sharedCache(store, identity, time.Second)
		c.chunks = sharedCache(store, identity, time.Second)
		return c
	}
	orgA, orgB := uuid.New(), uuid.New()
	a := chunkCache{c: replica("model-1").chunks, org: orgA}
	a.Store(ctx, map[string]fusion.Result{"w1": chunkResult(0.9), "w2": chunkResult(0.1)})

	// Another replica, same model and org: from the shared layer.
	got := chunkCache{c: replica("model-1").chunks, org: orgA}.Lookup(ctx, []string{"w1", "w2", "w3"})
	if len(got) != 2 || !reflect.DeepEqual(got["w1"], chunkResult(0.9)) {
		t.Fatalf("same org and model: %+v", got)
	}
	if got := (chunkCache{c: replica("model-1").chunks, org: orgB}).Lookup(ctx, []string{"w1", "w2"}); len(got) != 0 {
		t.Fatalf("another org read %+v", got)
	}
	if got := (chunkCache{c: replica("model-2").chunks, org: orgA}).Lookup(ctx, []string{"w1", "w2"}); len(got) != 0 {
		t.Fatalf("another model identity read %+v", got)
	}
	// In process, another org misses too.
	if got := (chunkCache{c: a.c, org: orgB}).Lookup(ctx, []string{"w1"}); len(got) != 0 {
		t.Fatalf("in process, another org read %+v", got)
	}
	// Only scores are stored, never a window's text.
	b, err := encodeShared("m", cacheChunk, chunkResult(0.5))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := decodeShared("m", cacheChunk, b); err != nil || !reflect.DeepEqual(v, chunkResult(0.5)) {
		t.Fatalf("round trip %+v %v", v, err)
	}
	if _, err := decodeShared("m", cacheSource, b); err == nil {
		t.Fatal("a chunk entry read as another kind")
	}
}

// The scan cache's identity changes with TOOL_CODE_CORROBORATION.
func TestConfigIdentity(t *testing.T) {
	var on, off config
	off.Scan.NoCodeCorroboration = true
	if configIdentity(on) == configIdentity(off) {
		t.Fatal("code corroboration not in the identity")
	}
	models := fixedIdentity("m")
	a, _ := waitIdentity(t, liveIdentity(models, configIdentity(on)))
	b, _ := waitIdentity(t, liveIdentity(models, configIdentity(off)))
	if a == b {
		t.Fatal("identities equal")
	}
}

func waitIdentity(t *testing.T, id func() (string, bool)) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := id(); ok {
			return s, ok
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("identity not ready")
	return "", false
}

const chatToolOutput = "src/main.go:12: func main() { fmt.Println(\"hello\") } // build output line\n"

func chatWithTool(tool, question string) string {
	return `{"model":"gpt-x","messages":[` +
		`{"role":"user","content":"Look at this file."},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/repo/x\"}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":` + jsonQuote(tool) + `},` +
		`{"role":"user","content":` + jsonQuote(question) + `}]}`
}

func chatGateway(t *testing.T) (*harness, *countingBackend) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}`))
	})
	var counter *countingBackend
	h := startGateway(t, up.URL, func(gw *gateway) {
		withCountingRunner(t, &counter)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
	})
	return h, counter
}

// Chat completions reuse a tool result's score on the next turn.
func TestChatCompletionsCacheToolResults(t *testing.T) {
	h, counter := chatGateway(t)
	tool := strings.Repeat(chatToolOutput, 200) // ~16 KB
	var scanned []int64
	for _, q := range []string{"What does it do?", "And why does it print hello?"} {
		before := counter.bytes.Load()
		if resp, got := h.post(t, "/v1/chat/completions", chatWithTool(tool, q), nil); resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, got)
		}
		scanned = append(scanned, counter.bytes.Load()-before)
	}
	if scanned[0] < int64(len(tool)) || scanned[1] >= int64(len(tool)/4) {
		t.Fatalf("bytes scanned per turn %v (tool output %d bytes)", scanned, len(tool))
	}
}

// A document scanned ahead with "cache": true is not scored again when a chat
// request carries it; without it, nothing is written.
func TestScanDocumentsCacheAhead(t *testing.T) {
	tool := strings.Repeat(chatToolOutput, 200)
	scan := `{"cache":%s,"documents":[{"id":"d","source":"tool","content":` + jsonQuote(tool) + `}]}`
	for _, cached := range []bool{false, true} {
		h, counter := chatGateway(t)
		flag := "false"
		if cached {
			flag = "true"
		}
		if resp, got := h.post(t, "/guardrail/scan", strings.Replace(scan, "%s", flag, 1), nil); resp.StatusCode != 200 {
			t.Fatalf("scan: %d %s", resp.StatusCode, got)
		}
		before := counter.bytes.Load()
		if resp, got := h.post(t, "/v1/chat/completions", chatWithTool(tool, "What does it do?"), nil); resp.StatusCode != 200 {
			t.Fatalf("chat: %d %s", resp.StatusCode, got)
		}
		scanned := counter.bytes.Load() - before
		if cached && scanned >= int64(len(tool)/4) || !cached && scanned < int64(len(tool)) {
			t.Fatalf("cache=%v: chat scanned %d bytes (document %d)", cached, scanned, len(tool))
		}
	}
}
