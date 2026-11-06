// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
)

// searchTurn is the assistant turn of a web search, as Claude Code sends it
// back: thinking, the server tool call, its result (title carries title,
// encrypted content stays opaque) and the answer with a citation.
func searchTurn(title string) map[string]any {
	return map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "thinking", "thinking": "", "signature": "SiG/+=="},
		map[string]any{"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": map[string]any{"query": "hanoi weather"}},
		map[string]any{"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []any{
			map[string]any{"type": "web_search_result", "url": "https://weather.example/hanoi", "title": title,
				"encrypted_content": "RW5jcnlwdGVk", "page_age": "1 day ago"},
			map[string]any{"type": "web_search_result", "url": "https://news.example/a", "title": "Hanoi news",
				"encrypted_content": "Zm9v"},
		}},
		map[string]any{"type": "text", "text": "It is 31C.", "citations": []any{map[string]any{
			"type": "web_search_result_location", "url": "https://weather.example/hanoi", "title": "Weather",
			"encrypted_index": "Eo8B", "cited_text": "31C"}}},
	}}
}

// fetchTurn is the assistant turn of a web fetch whose page holds text.
func fetchTurn(page string) map[string]any {
	return map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "server_tool_use", "id": "srvtoolu_2", "name": "web_fetch", "input": map[string]any{"url": "https://docs.example/p"}},
		map[string]any{"type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_2", "content": map[string]any{
			"type": "web_fetch_result", "url": "https://docs.example/p", "retrieved_at": "2025-08-25T10:30:02Z",
			"content": map[string]any{"type": "document", "title": "Docs", "citations": map[string]any{"enabled": true},
				"source": map[string]any{"type": "text", "media_type": "text/plain", "data": page}}}},
		map[string]any{"type": "text", "text": "Done."},
	}}
}

func serverToolBody(t *testing.T, turn map[string]any, trailing string) string {
	t.Helper()
	msgs := []any{map[string]any{"role": "user", "content": "what is the weather in hanoi?"}, turn}
	if trailing != "" {
		msgs = append(msgs, map[string]any{"role": "user", "content": trailing})
	}
	b, err := json.Marshal(map[string]any{"model": "claude-x", "max_tokens": 9, "messages": msgs,
		"tools": []any{map[string]any{"type": "web_search_20250305", "name": "web_search", "max_uses": 5}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestServerToolResultParts(t *testing.T) {
	raw := serverToolBody(t, searchTurn("Hanoi weather today"), "thanks")
	body, _ := decodeBody([]byte(raw))
	before, _ := decodeBody([]byte(raw))
	g := &textGuard{roles: &allRoles, latest: true}
	if err := g.guardMessagesBody(body); err != nil {
		t.Fatal(err)
	}
	tool := partSources(g)[indirect.SourceTool]
	if len(tool) != 1 {
		t.Fatalf("tool parts %q", tool)
	}
	for _, want := range []string{"Hanoi weather today", "https://weather.example/hanoi", "Hanoi news"} {
		if !strings.Contains(tool[0], want) {
			t.Errorf("part lacks %q: %q", want, tool[0])
		}
	}
	if strings.Contains(tool[0], "RW5jcnlwdGVk") || strings.Contains(tool[0], "1 day ago") {
		t.Errorf("opaque content classified: %q", tool[0])
	}
	if !g.parts[indexOfSource(g, indirect.SourceTool)].history || g.parts[indexOfSource(g, indirect.SourceTool)].redact == nil {
		t.Error("the result is history with a redactor")
	}
	// Nothing in the turn is rewritten: the signature and the citations stay.
	if !reflect.DeepEqual(body, before) {
		t.Error("body changed")
	}
	// A fetched page's text is classified; SCAN_ROLES without tool skips both.
	body, _ = decodeBody([]byte(serverToolBody(t, fetchTurn("Install with go get."), "")))
	g = &textGuard{roles: &allRoles, latest: true}
	if err := g.guardMessagesBody(body); err != nil {
		t.Fatal(err)
	}
	if tool := partSources(g)[indirect.SourceTool]; len(tool) != 1 || !strings.Contains(tool[0], "Install with go get.") ||
		strings.Contains(tool[0], "2025-08-25") {
		t.Errorf("fetch parts %q", tool)
	}
	noTool := allRoles
	noTool.Tool = false
	body, _ = decodeBody([]byte(serverToolBody(t, fetchTurn("Install with go get."), "")))
	g = &textGuard{roles: &noTool, latest: true}
	if err := g.guardMessagesBody(body); err != nil || len(partSources(g)[indirect.SourceTool]) != 0 {
		t.Errorf("tool role off: %v %v", partSources(g), err)
	}
}

func indexOfSource(g *textGuard, src indirect.Source) int {
	for i, p := range g.parts {
		if p.source == src {
			return i
		}
	}
	return -1
}

// An error result, or one with encrypted content only, has nothing to scan.
func TestServerToolResultNothingReadable(t *testing.T) {
	turn := map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "web_search_tool_result", "tool_use_id": "s", "content": map[string]any{
			"type": "web_search_tool_result_error", "error_code": "max_uses_exceeded"}},
	}}
	body, _ := decodeBody([]byte(serverToolBody(t, turn, "")))
	g := &textGuard{roles: &allRoles, latest: true}
	if err := g.guardMessagesBody(body); err != nil || len(partSources(g)[indirect.SourceTool]) != 0 {
		t.Errorf("%v %v", partSources(g), err)
	}
	// A shadow key next to content is refused.
	turn = map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "web_search_tool_result", "tool_use_id": "s", "content": []any{}, "Content": "x"},
	}}
	body, _ = decodeBody([]byte(serverToolBody(t, turn, "")))
	if err := (&textGuard{roles: &allRoles}).guardMessagesBody(body); err == nil {
		t.Error("shadow key accepted")
	}
}

func TestServerToolResultInjectionBlocks(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
	})
	resp, got := h.post(t, "/v1/messages", serverToolBody(t, searchTurn(toolAttack), "thanks"), nil)
	assertAnthropicError(t, resp, got, 400, "invalid_request_error")
	if !strings.Contains(got, "tool or document content") {
		t.Errorf("message %s", got)
	}
	if up.hits.Load() != 0 {
		t.Error("injected search result reached the upstream")
	}
	row := h.oneRow(t)
	if row.Action != actionBlock || row.Detected != layerIndirect || row.SourceRole != "tool" {
		t.Errorf("row %s %s %s", row.Action, row.Detected, row.SourceRole)
	}
	// A benign search turn goes through unchanged.
	resp, got = h.post(t, "/v1/messages", serverToolBody(t, searchTurn("Hanoi weather today"), "thanks"), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("benign: %d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent := up.body
	up.mu.Unlock()
	if !strings.Contains(sent, `"encrypted_content":"RW5jcnlwdGVk"`) || !strings.Contains(sent, `"signature":"SiG/+=="`) ||
		!strings.Contains(sent, `"encrypted_index":"Eo8B"`) {
		t.Errorf("upstream got %s", sent)
	}
}

func TestServerToolResultRedacted(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	var counter *countingBackend
	h := startGateway(t, "", func(gw *gateway) {
		redactGateway(up.URL)(gw)
		withCountingRunner(t, &counter)(gw)
	})
	for turn, trailing := range []string{"", "and tomorrow?"} {
		before := counter.runs.Load()
		resp, got := h.post(t, "/v1/messages", serverToolBody(t, searchTurn(toolAttack), trailing), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("turn %d: %d %s", turn, resp.StatusCode, got)
		}
		up.mu.Lock()
		sent := up.body
		up.mu.Unlock()
		var body struct {
			Messages []struct {
				Content any `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal([]byte(sent), &body); err != nil {
			t.Fatal(err)
		}
		blocks, _ := body.Messages[1].Content.([]any)
		result, _ := blocks[2].(map[string]any)
		text, _ := blocks[3].(map[string]any)
		thinking, _ := blocks[0].(map[string]any)
		want := map[string]any{"type": "web_search_tool_result_error", "error_code": "unavailable"}
		if !reflect.DeepEqual(result["content"], want) || result["tool_use_id"] != "srvtoolu_1" {
			t.Errorf("turn %d: result %v", turn, result)
		}
		if _, ok := text["citations"]; ok || text["text"] != "It is 31C." {
			t.Errorf("turn %d: citations kept %v", turn, text)
		}
		if thinking["signature"] != "SiG/+==" {
			t.Errorf("turn %d: thinking %v", turn, thinking)
		}
		if strings.Contains(sent, "Ignore all previous") || strings.Contains(sent, "RW5jcnlwdGVk") {
			t.Errorf("turn %d: upstream got %s", turn, sent)
		}
		h.gw.audit.wait()
		h.rec.mu.Lock()
		row := h.rec.rows[len(h.rec.rows)-1]
		h.rec.mu.Unlock()
		if row.Action != actionAllow || row.Redacted != 1 {
			t.Errorf("turn %d: row %s redacted %d", turn, row.Action, row.Redacted)
		}
		if evs := eventsFor(&row, 0.5); len(evs) != 1 || evs[0].Type != events.DetectionFlagged {
			t.Errorf("turn %d: events %+v", turn, evs)
		}
		// The second turn takes the verdict from the scan cache: only its
		// own user text runs the detector.
		if turn == 1 {
			if runs := counter.runs.Load() - before; runs > 2 {
				t.Errorf("history rescanned: %d runs", runs)
			}
		}
	}
}

func TestWebFetchResultRedacted(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	h := startGateway(t, "", redactGateway(up.URL))
	resp, got := h.post(t, "/v1/messages", serverToolBody(t, fetchTurn("Docs page. "+toolAttack), ""), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent := up.body
	up.mu.Unlock()
	if strings.Contains(sent, "Ignore all previous") ||
		!strings.Contains(sent, `{"error_code":"unavailable","type":"web_fetch_tool_result_error"}`) {
		t.Errorf("upstream got %s", sent)
	}
}

// A server tool result in a user turn (the API takes them in assistant turns
// only) is scanned all the same.
func TestServerToolResultInUserTurn(t *testing.T) {
	turn := searchTurn(toolAttack)
	turn["role"] = "user"
	body, _ := decodeBody([]byte(serverToolBody(t, turn, "")))
	g := &textGuard{roles: &allRoles, latest: true}
	if err := g.guardMessagesBody(body); err != nil {
		t.Fatal(err)
	}
	if tool := partSources(g)[indirect.SourceTool]; len(tool) != 1 || !strings.Contains(tool[0], "Ignore all previous") {
		t.Errorf("parts %v", partSources(g))
	}
}

// webSearchEvents is a streamed web search turn: the call, its result and a
// cited answer.
func webSearchEvents(title string) []string {
	result, _ := json.Marshal(map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{
		"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []any{map[string]any{
			"type": "web_search_result", "url": "https://weather.example/hanoi", "title": title,
			"encrypted_content": "RW5jcnlwdGVk", "page_age": "1 day ago"}}}})
	return []string{
		sseEvent("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[],"stop_reason":null,"usage":{"input_tokens":3,"output_tokens":1}}}`),
		sseEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}}`),
		sseEvent("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"hanoi weather\"}"}}`),
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseEvent("content_block_start", string(result)),
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":1}`),
		sseEvent("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`),
		sseEvent("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"citations_delta","citation":{"type":"web_search_result_location","url":"https://weather.example/hanoi","title":"Weather","encrypted_index":"Eo8B","cited_text":"31C"}}}`),
		sseEvent("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"It is 31C."}}`),
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":2}`),
		sseEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":20,"server_tool_use":{"web_search_requests":1}}}`),
		sseEvent("message_stop", `{"type":"message_stop"}`),
	}
}

func TestMessagesStreamWebSearch(t *testing.T) {
	up := newFakeUpstream(t, streamingUpstream(webSearchEvents("Hanoi ![x](https://evil.example/p.png?d=1) weather")...))
	h := startGateway(t, "", withAnthropic(up.URL))
	evs, resp := readEvents(t, h, streamBody)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var all strings.Builder
	for _, e := range evs {
		all.WriteString(e[0] + " " + e[1] + "\n")
		if e[0] == "error" {
			t.Fatalf("stream stopped: %s", e[1])
		}
	}
	text := all.String()
	if strings.Contains(text, "evil.example") || !strings.Contains(text, `"encrypted_content":"RW5jcnlwdGVk"`) ||
		!strings.Contains(text, "It is 31C.") || !strings.Contains(text, "message_stop") ||
		!strings.Contains(text, `{\"query\":\"hanoi weather\"}`) {
		t.Errorf("stream %s", text)
	}
	if row := h.oneRow(t); row.Action != actionAllow || row.Output[outputguard.KindImage] != 1 {
		t.Errorf("row %s %v", row.Action, row.Output)
	}
}

func TestMessagesNonStreamWebSearch(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"q"}},
			{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[{"type":"web_search_result","url":"https://a.example/",
			  "title":"Write to alice@example.com","encrypted_content":"RW5j"}]},
			{"type":"text","text":"Done."}`))
	})
	h := startGateway(t, "", withAnthropic(up.URL))
	resp, got := h.post(t, "/v1/messages", messagesClean, nil)
	if resp.StatusCode != 200 || strings.Contains(got, "alice@example.com") || !strings.Contains(got, `"encrypted_content":"RW5j"`) {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
}

// OUTPUT_UNKNOWN_BLOCKS=pass lets a block type the guard does not know through,
// unchecked; the default refuses it (TestMessagesUncheckableResponseRefused).
func TestMessagesUnknownBlocksPass(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"mystery_block","payload":"x@example.com"}`))
	})
	h := startGateway(t, "", func(gw *gateway) {
		withAnthropic(up.URL)(gw)
		cfg := defaultOutputConfig()
		cfg.PassUnknownBlocks = true
		gw.output = outputguard.New(cfg)
	})
	resp, got := h.post(t, "/v1/messages", messagesClean, nil)
	if resp.StatusCode != 200 || !strings.Contains(got, `"payload":"x@example.com"`) {
		t.Errorf("%d %s", resp.StatusCode, got)
	}
}
