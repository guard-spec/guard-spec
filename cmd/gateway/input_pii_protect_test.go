// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
)

func piiActionOn(t testing.TB, raw string) settingsLoader {
	t.Helper()
	s, err := indirect.ParseSettings([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, uuid.UUID) (indirect.Settings, error) { return s, nil }
}

// The upstream answers with the tokens it was given; the pieces split the
// tokens across stream events.
const tokenAnswer = "Đã gửi ⟦EMAIL_1⟧ và ⟦PHONE_1⟧ nhé"

var tokenPieces = []string{"Đã gửi ⟦EMA", "IL_1⟧ và ⟦", "PHONE_", "1⟧ nhé"}

const restoredAnswer = "Đã gửi lan.nguyen@congty.vn và 0912 345 678 nhé"

func tokenAPIs() []piiAPI {
	user := jsonQuote(piiUser)
	chatStream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		var b strings.Builder
		for _, p := range tokenPieces {
			b.WriteString(sseChunk(p, nil))
		}
		b.WriteString(sseChunk("", "stop") + "data: [DONE]\n\n")
		_, _ = w.Write([]byte(b.String()))
	}
	msgEvents := []string{
		sseEvent("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-x","usage":{"input_tokens":3,"output_tokens":1}}}`),
		sseEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
	}
	for _, p := range tokenPieces {
		msgEvents = append(msgEvents, textDelta(p))
	}
	msgEvents = append(msgEvents,
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`),
		sseEvent("message_stop", `{"type":"message_stop"}`))
	respEvents := []string{
		responsesSSE("response.created", `,"response":{"id":"resp_1","object":"response","status":"in_progress","output":[]}`),
		responsesSSE("response.output_item.added", `,"output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","content":[]}`),
		responsesSSE("response.content_part.added", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}`),
	}
	for _, p := range tokenPieces {
		respEvents = append(respEvents, responsesSSE("response.output_text.delta",
			`,"item_id":"msg_1","output_index":0,"content_index":0,"delta":`+jsonQuote(p)+`,"logprobs":[]`))
	}
	respEvents = append(respEvents,
		responsesSSE("response.output_text.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"text":`+jsonQuote(tokenAnswer)+`,"logprobs":[]`),
		responsesSSE("response.content_part.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":`+jsonQuote(tokenAnswer)+`,"annotations":[]}`),
		responsesSSE("response.output_item.done", `,"output_index":0,"item":`+textItem(tokenAnswer)),
		responsesSSE("response.completed", `,"response":`+responseObject(textItem(tokenAnswer))))
	chatJSON := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":` + jsonQuote(tokenAnswer) + `}}]}`))
	}
	return []piiAPI{
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"m","messages":[{"role":"user","content":` + user + `}]}`, upstream: chatJSON},
		{name: "chat stream", path: "/v1/chat/completions", upstream: chatStream,
			body: `{"model":"m","stream":true,"messages":[{"role":"user","content":` + user + `}]}`},
		{name: "messages", path: "/v1/messages", anthropic: true,
			body: `{"model":"claude-x","max_tokens":10,"messages":[{"role":"user","content":` + user + `}]}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				anthropicJSON(w, messageResponse(`{"type":"text","text":`+jsonQuote(tokenAnswer)+`}`))
			}},
		{name: "messages stream", path: "/v1/messages", anthropic: true, upstream: streamingUpstream(msgEvents...),
			body: `{"model":"claude-x","max_tokens":10,"stream":true,"messages":[{"role":"user","content":` + user + `}]}`},
		{name: "responses", path: "/v1/responses", body: `{"model":"m","input":` + user + `}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem(tokenAnswer))) }},
		{name: "responses stream", path: "/v1/responses", body: `{"model":"m","stream":true,"input":` + user + `}`,
			upstream: streamingUpstream(respEvents...)},
	}
}

// tokenize: the upstream sees tokens, never the values; the client gets the
// values back, streamed or not, with the output guard off and on.
func TestPIITokenizeThroughGateway(t *testing.T) {
	for _, api := range tokenAPIs() {
		for _, guardOn := range []bool{false, true} {
			name := api.name
			if guardOn {
				name += "/output guard"
			}
			t.Run(name, func(t *testing.T) {
				up := newFakeUpstream(t, api.upstream)
				upURL := up.URL
				if api.anthropic {
					upURL = ""
				}
				h := startGateway(t, upURL, func(gw *gateway) {
					if api.anthropic {
						withAnthropic(up.URL)(gw)
					}
					gw.settings = piiActionOn(t, `{"input_pii_action":"tokenize"}`)
					gw.output = nil
					if guardOn {
						gw.output = outputguard.New(outputguard.Config{LinkAllowlist: []string{"example.com"}})
					}
				})
				resp, got := h.post(t, api.path, api.body, nil)
				if resp.StatusCode != 200 {
					t.Fatalf("status %d: %s", resp.StatusCode, got)
				}
				up.mu.Lock()
				sent := up.body
				up.mu.Unlock()
				noValues(t, "upstream body", sent)
				if !strings.Contains(sent, "⟦EMAIL_1⟧") || !strings.Contains(sent, "⟦PHONE_1⟧") {
					t.Errorf("upstream body lacks the tokens: %s", sent)
				}
				text := got
				if strings.Contains(api.body, `"stream":true`) {
					text = joinStreamText(got)
				}
				if !strings.Contains(text, restoredAnswer) || strings.Contains(text, "⟦") {
					t.Errorf("client got %q, want %q", text, restoredAnswer)
				}
				tags := auditTags(h.oneRow(t))
				if !slices.Contains(tags, "input:pii_tokenized_email=1") || !slices.Contains(tags, "input:pii_tokenized_phone=1") {
					t.Errorf("tags %v", tags)
				}
				noValues(t, "audit tags", tags...)
			})
		}
	}
}

// joinStreamText concatenates the text deltas of the three APIs' streams.
func joinStreamText(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		switch {
		case ev["object"] == "chat.completion.chunk":
			for _, c := range ev["choices"].([]any) {
				if d, ok := c.(map[string]any)["delta"].(map[string]any); ok {
					s, _ := d["content"].(string)
					b.WriteString(s)
				}
			}
		case ev["type"] == "content_block_delta":
			d, _ := ev["delta"].(map[string]any)
			s, _ := d["text"].(string)
			b.WriteString(s)
		case ev["type"] == "response.output_text.delta":
			s, _ := ev["delta"].(string)
			b.WriteString(s)
		}
	}
	return b.String()
}

// redact: labels upstream, and the answer keeps them.
func TestPIIRedactThroughGateway(t *testing.T) {
	api := tokenAPIs()[0]
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		gw.settings = piiActionOn(t, `{"input_pii_action":"redact","input_pii_kinds":["email"]}`)
	})
	if resp, got := h.post(t, api.path, api.body, nil); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent := up.body
	up.mu.Unlock()
	if strings.Contains(sent, "lan.nguyen@congty.vn") || !strings.Contains(sent, "[EMAIL]") {
		t.Errorf("email not redacted: %s", sent)
	}
	if !strings.Contains(sent, "0912 345 678") {
		t.Errorf("phone redacted though only email was selected: %s", sent)
	}
	if tags := auditTags(h.oneRow(t)); !slices.Contains(tags, "input:pii_redacted_email=1") {
		t.Errorf("tags %v", tags)
	}
}

// The conversation the client sends back holds the values the answers got
// back: earlier assistant text and tool-call arguments are tokenized too, with
// the same token for the same value; the system prompt is left alone.
func TestPIITokenizeConversation(t *testing.T) {
	body := `{"model":"m","messages":[` +
		`{"role":"system","content":"Support: help@acme.example"},` +
		`{"role":"user","content":` + jsonQuote(piiUser) + `},` +
		`{"role":"assistant","content":"Đã gửi lan.nguyen@congty.vn","tool_calls":[{"id":"c1","type":"function","function":{"name":"send","arguments":"{\"to\":\"lan.nguyen@congty.vn\",\"n\":912345678}"}}]},` +
		`{"role":"tool","tool_call_id":"c1","content":"sent to lan.nguyen@congty.vn"},` +
		`{"role":"user","content":"cảm ơn"}]}`
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		gw.settings = piiActionOn(t, `{"input_pii_action":"tokenize"}`)
	})
	if resp, got := h.post(t, "/v1/chat/completions", body, nil); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	sent := up.body
	up.mu.Unlock()
	if strings.Contains(sent, "lan.nguyen@congty.vn") {
		t.Errorf("a value went upstream: %s", sent)
	}
	if n := strings.Count(sent, "⟦EMAIL_1⟧"); n != 4 {
		t.Errorf("EMAIL_1 %d times, want 4: %s", n, sent)
	}
	if !strings.Contains(sent, "help@acme.example") {
		t.Errorf("the system prompt was changed: %s", sent)
	}
	if !strings.Contains(sent, `\"n\":912345678`) {
		t.Errorf("a JSON number in the arguments was changed: %s", sent)
	}
}

func TestParsePIIActionSettings(t *testing.T) {
	for _, bad := range []string{`{"input_pii_action":"mask"}`, `{"input_pii_kinds":["name"]}`} {
		if _, err := indirect.ParseSettings([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	s, err := indirect.ParseSettings([]byte(`{"input_pii_action":"tokenize","input_pii_kinds":["email","cccd"]}`))
	if err != nil || !s.PII() || s.PIIAction() != "tokenize" {
		t.Fatalf("%+v %v", s, err)
	}
	if off, _ := indirect.ParseSettings([]byte(`{}`)); off.PII() || off.PIIAction() != "off" {
		t.Error("defaults")
	}
}

// The same for the Messages API (assistant text and tool_use input; thinking
// left alone) and the Responses API (assistant messages and function_call
// arguments).
func TestPIITokenizeConversationOtherAPIs(t *testing.T) {
	cases := []struct {
		name, path, body, keep string
		anthropic              bool
	}{
		{"messages", "/v1/messages", `{"model":"claude-x","max_tokens":10,"messages":[` +
			`{"role":"user","content":` + jsonQuote(piiUser) + `},` +
			`{"role":"assistant","content":[{"type":"thinking","thinking":"mail lan.nguyen@congty.vn","signature":"sig"},` +
			`{"type":"text","text":"Gửi lan.nguyen@congty.vn"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"lan.nguyen@congty.vn"}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}]}`, "mail lan.nguyen@congty.vn", true},
		{"responses", "/v1/responses", `{"model":"m","input":[` +
			`{"role":"user","content":` + jsonQuote(piiUser) + `},` +
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Gửi lan.nguyen@congty.vn"}]},` +
			`{"type":"function_call","call_id":"c1","name":"send","arguments":"{\"to\":\"lan.nguyen@congty.vn\"}"},` +
			`{"type":"function_call_output","call_id":"c1","output":"ok"}]}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem("ok"))) }
			if c.anthropic {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
				}
			}
			up := newFakeUpstream(t, handler)
			upURL := up.URL
			if c.anthropic {
				upURL = ""
			}
			h := startGateway(t, upURL, func(gw *gateway) {
				if c.anthropic {
					withAnthropic(up.URL)(gw)
				}
				gw.settings = piiActionOn(t, `{"input_pii_action":"tokenize"}`)
			})
			if resp, got := h.post(t, c.path, c.body, nil); resp.StatusCode != 200 {
				t.Fatalf("%d %s", resp.StatusCode, got)
			}
			up.mu.Lock()
			sent := up.body
			up.mu.Unlock()
			rest := strings.ReplaceAll(sent, c.keep, "")
			if c.keep != "" && !strings.Contains(sent, c.keep) {
				t.Errorf("the signed thinking block was changed: %s", sent)
			}
			if strings.Contains(rest, "lan.nguyen@congty.vn") {
				t.Errorf("a value went upstream: %s", sent)
			}
			if n := strings.Count(sent, "⟦EMAIL_1⟧"); n != 3 {
				t.Errorf("EMAIL_1 %d times, want 3: %s", n, sent)
			}
		})
	}
}
