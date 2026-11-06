// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

func TestScanCache(t *testing.T) {
	c := newScanCache(2, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	org := uuid.New()
	a, b, d := cacheKey(org, "k", "a"), cacheKey(org, "k", "b"), cacheKey(org, "k", "d")
	if cacheKey(org, "k", "ab", "c") == cacheKey(org, "k", "a", "bc") || cacheKey(uuid.New(), "k", "a") == a {
		t.Error("keys collide")
	}
	c.put(1, a, 1)
	c.put(1, b, 2)
	c.get(1, a) // a is now the most recent
	c.put(1, d, 3)
	if _, ok := c.get(1, b); ok {
		t.Error("least recent entry kept")
	}
	if v, ok := c.get(1, a); !ok || v != 1 {
		t.Error("recent entry evicted")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.get(1, a); ok {
		t.Error("expired entry returned")
	}
	c.put(1, a, 1)
	if _, ok := c.get(2, a); ok || c.len() != 0 {
		t.Error("a new model generation kept the cache")
	}
	var off *scanCache
	off.put(1, a, 1)
	if _, ok := off.get(1, a); ok || newScanCache(0, time.Minute) != nil {
		t.Error("cache off")
	}
}

// A Claude Code session: three earlier turns and the trailing one.
func sessionBody(toolOutputs []string, trailingUser string) string {
	var msgs []any
	msgs = append(msgs, map[string]any{"role": "user", "content": "first question"})
	for i, out := range toolOutputs {
		id := "toolu_" + string(rune('a'+i))
		msgs = append(msgs,
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": id, "name": "Bash",
				"input": map[string]any{"command": "cat f"}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": out}}})
	}
	if trailingUser != "" {
		msgs = append(msgs, map[string]any{"role": "assistant", "content": "done"},
			map[string]any{"role": "user", "content": trailingUser})
	}
	b, _ := json.Marshal(map[string]any{"model": "claude-x", "max_tokens": 9, "system": "You are a coding agent.",
		"messages": msgs, "tools": []any{map[string]any{"name": "Bash", "description": "Runs a command.",
			"input_schema": map[string]any{"type": "object"}}}})
	return string(b)
}

func TestLatestHistoryParts(t *testing.T) {
	body, _ := decodeBody([]byte(sessionBody([]string{"out one", "out two"}, "next question")))
	g := &textGuard{roles: &allRoles, latest: true}
	if err := g.guardMessagesBody(body); err != nil {
		t.Fatal(err)
	}
	got := partSources(g)
	if strings.Join(got[indirect.SourceUser], "|") != "next question" || len(got[indirect.SourceAssistant]) != 0 {
		t.Errorf("history text classified: %v", got)
	}
	// Earlier tool results stay parts: they go through the scan cache.
	if strings.Join(got[indirect.SourceTool], "|") != "out one|out two" {
		t.Errorf("tool parts %v", got[indirect.SourceTool])
	}
	for _, p := range g.parts {
		if p.source == indirect.SourceSystem && !p.alone {
			t.Error("system not scored alone")
		}
	}
	// SCAN_HISTORY=full classifies every turn.
	body, _ = decodeBody([]byte(sessionBody([]string{"out one"}, "next question")))
	g = &textGuard{roles: &allRoles}
	if err := g.guardMessagesBody(body); err != nil {
		t.Fatal(err)
	}
	if got := partSources(g); len(got[indirect.SourceUser]) != 2 || len(got[indirect.SourceAssistant]) != 1 {
		t.Errorf("full: %v", got)
	}
}

// countingBackend counts detector runs.
type countingBackend struct {
	inner inference.ModelBackend
	runs  atomic.Int64
	bytes atomic.Int64
}

func (b *countingBackend) Run(ctx context.Context, text string) ([]inference.Score, error) {
	b.runs.Add(1)
	b.bytes.Add(int64(len(text)))
	return b.inner.Run(ctx, text)
}

func withCountingRunner(t *testing.T, counter **countingBackend) func(*gateway) {
	return func(gw *gateway) {
		cb := &countingBackend{inner: inference.FusedBackend{F: fusion.New()}}
		*counter = cb
		gw.runner = inference.NewRunnerWith(cb)
	}
}

// Every turn resends the session; each tool output is about 20 KB, so the
// session passes 128 KB of tool output. Only the new output is classified.
func TestLongSessionScansOnlyNewContent(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	var counter *countingBackend
	h := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		withCountingRunner(t, &counter)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
	})
	chunk := strings.Repeat("src/main.go:12: func main() { fmt.Println(\"hello\") }\n", 400) // ~21 KB
	var outputs []string
	for turn := range 8 {
		outputs = append(outputs, chunk+string(rune('A'+turn)))
		before := counter.bytes.Load()
		resp, got := h.post(t, "/v1/messages", sessionBody(outputs, ""), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("turn %d: %d %s", turn, resp.StatusCode, got)
		}
		// The new output and the trailing text; not the earlier outputs.
		if scanned := counter.bytes.Load() - before; scanned > int64(len(chunk))*2 {
			t.Errorf("turn %d scanned %d bytes", turn, scanned)
		}
	}
	if total := 8 * len(chunk); total < maxUntrustedBytes {
		t.Fatalf("session too short: %d", total)
	}
	// With SCAN_HISTORY=full the same session is refused for its size.
	h2 := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
		gw.scan = &scanConfig{Roles: indirect.DefaultRoles, IndirectThreshold: 0.85, IndirectAction: indirect.ActionBlock,
			History: historyFull}
	})
	resp, got := h2.post(t, "/v1/messages", sessionBody(outputs, ""), nil)
	assertAnthropicError(t, resp, got, 413, "request_too_large")
	// A gateway that never saw the earlier turns (restart, another replica)
	// scans them once, within the larger history budget.
	h3 := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
	})
	if resp, got := h3.post(t, "/v1/messages", sessionBody(outputs, "and now?"), nil); resp.StatusCode != 200 {
		t.Errorf("cold cache: %d %s", resp.StatusCode, got)
	}
}

// A tool output longer than one runner call is scored in segments, every
// byte of it: a payload at the end is still found.
func TestLongToolOutputSegments(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	h := startGateway(t, "", withAnthropic(up.URL))
	long := strings.Repeat("log line: build step finished without errors\n", 1400) // ~64 KB
	if resp, got := h.post(t, "/v1/messages", sessionBody([]string{long}, ""), nil); resp.StatusCode != 200 {
		t.Fatalf("long benign output: %d %s", resp.StatusCode, got)
	}
	resp, got := h.post(t, "/v1/messages", sessionBody([]string{long + toolAttack}, ""), nil)
	assertAnthropicError(t, resp, got, 400, "invalid_request_error")
}

func redactGateway(up string) func(*gateway) {
	return func(gw *gateway) {
		withAnthropic(up)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
		gw.scan = &scanConfig{Roles: indirect.DefaultRoles, IndirectThreshold: 0.85, IndirectAction: indirect.ActionRedact,
			History: historyLatest}
	}
}

func TestRedactToolResult(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	h := startGateway(t, "", redactGateway(up.URL))
	body := sessionBody([]string{"benign output", toolAttack}, "")
	resp, got := h.post(t, "/v1/messages", body, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent := up.body
	up.mu.Unlock()
	if strings.Contains(sent, "Ignore all previous") || !strings.Contains(sent, redactedToolOutput) ||
		!strings.Contains(sent, `"is_error":true`) || !strings.Contains(sent, "benign output") {
		t.Errorf("upstream got %s", sent)
	}
	row := h.oneRow(t)
	if row.Action != actionAllow || row.Redacted != 1 || row.Indirect.Score < 0.85 || row.SourceRole != "tool" {
		t.Errorf("row action %s redacted %d score %v", row.Action, row.Redacted, row.Indirect.Score)
	}
	if tags := auditTags(row); len(tags) != 1 || tags[0] != "input:redacted=1" {
		t.Errorf("tags %v", tags)
	}
	evs := eventsFor(&row, 0.5)
	if len(evs) != 1 || evs[0].Type != events.DetectionFlagged || evs[0].Attrs["decision"] != decisionRedact {
		t.Errorf("events %+v", evs)
	}

	// The next turn resends the original output in history: it is redacted
	// again from the cache, without running the detector on it.
	h.rec.mu.Lock()
	h.rec.rows = nil
	h.rec.mu.Unlock()
	resp, got = h.post(t, "/v1/messages", sessionBody([]string{"benign output", toolAttack}, "and now?"), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("next turn: %d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent = up.body
	up.mu.Unlock()
	if strings.Contains(sent, "Ignore all previous") || !strings.Contains(sent, redactedToolOutput) {
		t.Errorf("history not redacted: %s", sent)
	}
	if row := h.oneRow(t); row.Redacted != 1 {
		t.Errorf("next turn row %+v", row.Redacted)
	}
}

func TestRedactKeepsToolDescriptionBlock(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, "", redactGateway(up.URL))
	d, _ := json.Marshal(poisonedEN)
	resp, got := h.post(t, "/v1/messages", `{"model":"claude-x","max_tokens":9,"messages":[{"role":"user","content":"add 1 and 2"}],
		"tools":[{"name":"add","description":`+string(d)+`,"input_schema":{"type":"object"}}]}`, nil)
	assertAnthropicError(t, resp, got, 400, "invalid_request_error")
	if up.hits.Load() != 0 {
		t.Error("poisoned tool reached the upstream")
	}
}

// In block mode a refused tool result in history keeps refusing the session.
func TestBlockedToolResultInHistoryStillBlocks(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
	})
	for _, trailing := range []string{"", "next question"} {
		resp, got := h.post(t, "/v1/messages", sessionBody([]string{toolAttack}, trailing), nil)
		assertAnthropicError(t, resp, got, 400, "invalid_request_error")
	}
	if up.hits.Load() != 0 {
		t.Error("blocked content reached the upstream")
	}
}

// The chat path redacts a tool message the same way.
func TestRedactChatToolMessage(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		gw.scan = &scanConfig{Roles: indirect.DefaultRoles, IndirectThreshold: 0.85, IndirectAction: indirect.ActionRedact,
			History: historyLatest}
	})
	resp, got := h.post(t, "/v1/chat/completions", chatBody(`[{"role":"user","content":"weather?"},
		{"role":"tool","tool_call_id":"c","content":"`+toolAttack+`"}]`, ""), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d %s", resp.StatusCode, got)
	}
	if strings.Contains(up.body, "Ignore all previous") || !strings.Contains(up.body, redactedToolOutput) {
		t.Errorf("upstream got %s", up.body)
	}
}

func TestIndirectActionSetting(t *testing.T) {
	s, err := indirect.ParseSettings([]byte(`{"indirect_action":"redact"}`))
	if err != nil || s.Action(indirect.ActionBlock) != indirect.ActionRedact {
		t.Errorf("%+v %v", s, err)
	}
	if _, err := indirect.ParseSettings([]byte(`{"indirect_action":"drop"}`)); err == nil {
		t.Error("bad action accepted")
	}
	h := startGateway(t, "", func(gw *gateway) {
		gw.settings = func(context.Context, uuid.UUID) (indirect.Settings, error) { return s, nil }
	})
	cfg, err := h.gw.scanConfigFor(devOrg)
	if err != nil || cfg.IndirectAction != indirect.ActionRedact {
		t.Errorf("org override: %+v %v", cfg, err)
	}
}
