// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/policy"
)

// Personal data of the tests: none of these values may show up in what the
// gateway keeps (audit row, events, logs of the match).
const (
	piiUser   = "Gửi hợp đồng cho lan.nguyen@congty.vn, SĐT 0912 345 678 nhé"
	piiTool   = "Customer card 4111 1111 1111 1111, CCCD 079203001234"
	piiSystem = "Example data: support@example.com, +84 912 345 679, 10.0.0.1"
)

var piiValues = []string{"lan.nguyen@congty.vn", "0912 345 678", "4111 1111 1111 1111", "079203001234",
	"support@example.com", "congty", "4111", "0912"}

func piiOn(t testing.TB, on bool) settingsLoader {
	t.Helper()
	raw := `{}`
	if on {
		raw = `{"input_pii":true}`
	}
	s, err := indirect.ParseSettings([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, uuid.UUID) (indirect.Settings, error) { return s, nil }
}

func noValues(t *testing.T, where string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		for _, v := range piiValues {
			if strings.Contains(s, v) {
				t.Errorf("%s holds %q: %s", where, v, s)
			}
		}
	}
}

// With the setting off the check does no work: the detectors are never
// called and nothing is counted. On, they run once per checked text.
// (BenchmarkInputPII measures the time.)
func TestInputPIIOffCostsNothing(t *testing.T) {
	calls := 0
	prev := piiCounter
	piiCounter = func(text string) outputguard.Counts { calls++; return prev(text) }
	t.Cleanup(func() { piiCounter = prev })
	body := chatBody(messages("system", piiSystem, "user", piiUser, "tool", piiTool), "")
	for _, on := range []bool{false, true} {
		calls = 0
		b, err := decodeBody([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		g := textGuard{detectPII: on}
		if err := g.guardBody(b); err != nil {
			t.Fatal(err)
		}
		want := 0
		if on {
			want = 2 // the user turn and the tool result; not the system prompt
		}
		if calls != want || (g.pii != nil) != on {
			t.Errorf("input_pii %v: %d detector calls, pii %v", on, calls, g.pii)
		}
	}
}

// Which text counts: user turns (every part), tool results and documents;
// never system or developer prompts, tool-call arguments or tool
// descriptions, even when they are scanned for injection.
func TestInputPIICollectChat(t *testing.T) {
	body := `{"model":"m","messages":[
		{"role":"system","content":` + jsonQuote(piiSystem) + `},
		{"role":"user","content":[{"type":"text","text":"Hello"},{"type":"text","text":` + jsonQuote(piiUser) + `}]},
		{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"crm","arguments":"{\"q\":\"boss@example.com\"}"}}]},
		{"role":"tool","tool_call_id":"c","content":` + jsonQuote(piiTool) + `}],
		"tools":[{"type":"function","function":{"name":"crm","description":"Looks up admin@example.com","parameters":{}}}]}`
	want := outputguard.Counts{"email": 1, "phone": 1, "card": 1, "cccd": 1}
	for _, tt := range []struct {
		name  string
		roles indirect.Roles
		on    bool
		want  outputguard.Counts
	}{
		{"default roles", indirect.DefaultRoles, true, want},
		{"every role scanned: system and tool calls still left out", allRoles, true, want},
		{"switch off", allRoles, false, nil},
		{"user turns not scanned", indirect.Roles{Tool: true}, true, outputguard.Counts{"card": 1, "cccd": 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := decodeBody([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			g := &textGuard{roles: &tt.roles, detectPII: tt.on}
			if err := g.guardBody(b); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(g.pii, tt.want) || (tt.want == nil) != (g.pii == nil) {
				t.Errorf("pii = %v, want %v", g.pii, tt.want)
			}
		})
	}
}

// Every user turn counts on chat; a legacy prompt and suffix are user text.
func TestInputPIICollectTurnsAndLegacy(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
		want             outputguard.Counts
	}{
		{"earlier turns", "/v1/chat/completions", chatBody(messages("user", "mail a@example.com", "assistant", "ok",
			"user", "and b@example.com, 0912345678"), ""), outputguard.Counts{"email": 2, "phone": 1}},
		{"legacy prompt and suffix", "/v1/completions", `{"prompt":["call 0912345678"],"suffix":"ip 192.168.1.1"}`,
			outputguard.Counts{"phone": 1, "ipv4": 1}},
		{"nothing", "/v1/chat/completions", chatBody(messages("user", "Order #A-20231108-7781, v1.2.3"), ""), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := decodeBody([]byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			g := &textGuard{detectPII: true}
			if err := g.guardBody(b); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(g.pii, tt.want) {
				t.Errorf("pii = %v, want %v", g.pii, tt.want)
			}
		})
	}
}

// The Messages API: the system prompt (string or blocks, or a system message
// among the turns) is left out; user text, tool_result content, documents
// and search results count, earlier turns too with SCAN_HISTORY=latest.
func TestInputPIICollectMessages(t *testing.T) {
	body := `{"model":"claude-x","max_tokens":10,
		"system":[{"type":"text","text":` + jsonQuote(piiSystem) + `}],
		"messages":[
		{"role":"user","content":"my mail is old@example.com"},
		{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"crm","input":{"q":"boss@example.com"}}]},
		{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":` + jsonQuote(piiTool) + `}]},
			{"type":"document","source":{"type":"text","media_type":"text/plain","data":"Server 203.0.113.9"}},
			{"type":"search_result","source":"https://x.example","title":"t","content":[{"type":"text","text":"hotline 02838234567"}]},
			{"type":"text","text":` + jsonQuote(piiUser) + `}]}]}`
	for _, latest := range []bool{false, true} {
		b, err := decodeBody([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		g := &textGuard{roles: &allRoles, detectPII: true, latest: latest}
		if err := g.guardMessagesBody(b); err != nil {
			t.Fatal(err)
		}
		want := outputguard.Counts{"email": 2, "phone": 2, "card": 1, "cccd": 1, "ipv4": 1}
		if !maps.Equal(g.pii, want) {
			t.Errorf("latest %v: pii = %v, want %v", latest, g.pii, want)
		}
	}
}

// The Responses API: instructions and system or developer messages are left
// out; input text, prompt variables and tool output items count.
func TestInputPIICollectResponses(t *testing.T) {
	body := `{"model":"m","instructions":` + jsonQuote(piiSystem) + `,
		"prompt":{"id":"p","variables":{"customer":"x@example.com"}},
		"input":[
		{"role":"developer","content":"Never mail dev@example.com"},
		{"role":"user","content":[{"type":"input_text","text":` + jsonQuote(piiUser) + `}]},
		{"type":"function_call","call_id":"c","name":"crm","arguments":"{\"q\":\"boss@example.com\"}"},
		{"type":"function_call_output","call_id":"c","output":` + jsonQuote(piiTool) + `}]}`
	g, _, err := guardResponses(t, body, func(g *textGuard) { g.detectPII = true })
	if err != nil {
		t.Fatal(err)
	}
	want := outputguard.Counts{"email": 2, "phone": 1, "card": 1, "cccd": 1}
	if !maps.Equal(g.pii, want) {
		t.Errorf("pii = %v, want %v", g.pii, want)
	}
}

func TestPIIVarsAndTags(t *testing.T) {
	counts := outputguard.Counts{"ipv4": 1, "email": 2, "cccd": 1}
	kinds, n := piiVars(counts)
	if !slices.Equal(kinds, []string{"email", "cccd", "ipv4"}) || n != 4 {
		t.Errorf("vars = %v %d", kinds, n)
	}
	if kinds, n := piiVars(nil); kinds != nil || n != 0 {
		t.Errorf("nil: %v %d", kinds, n)
	}
	tags := auditTags(requestEntry{InputPII: counts, Output: outputguard.Counts{"email": 1}})
	want := []string{"output:email=1", "input:pii_email=2", "input:pii_cccd=1", "input:pii_ipv4=1"}
	if !slices.Equal(tags, want) {
		t.Errorf("tags = %v, want %v", tags, want)
	}
}

// A detection event carries the kinds and the count, never the values.
func TestInputPIIEvent(t *testing.T) {
	rule := uuid.New()
	e := requestEntry{ID: uuid.New(), OrgID: uuid.New(), Action: actionBlock, Detected: layerPolicy, RuleID: rule,
		InputPII: outputguard.Counts{"email": 1, "card": 2}}
	evs := eventsFor(&e, 0.5)
	if len(evs) != 1 || evs[0].Type != events.DetectionBlocked || evs[0].Attrs["policy_id"] != rule.String() ||
		!slices.Equal(evs[0].Attrs["pii_kinds"].([]string), []string{"email", "card"}) || evs[0].Attrs["pii_count"] != 3 {
		t.Errorf("events %+v", evs)
	}
	e.InputPII = nil
	if evs := eventsFor(&e, 0.5); evs[0].Attrs["pii_kinds"] != nil || evs[0].Attrs["pii_count"] != nil {
		t.Errorf("attrs without personal data: %+v", evs[0].Attrs)
	}
}

// piiAPI is one of the three APIs, non-stream and stream.
type piiAPI struct {
	name, path, body string
	upstream         http.HandlerFunc
	anthropic        bool
}

func piiAPIs() []piiAPI {
	chatStream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseChunk("ok", nil) + sseChunk("", "stop") + "data: [DONE]\n\n"))
	}
	msgStream := streamingUpstream(
		sseEvent("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-x","usage":{"input_tokens":3,"output_tokens":1}}}`),
		sseEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
		textDelta("ok"),
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`),
		sseEvent("message_stop", `{"type":"message_stop"}`),
	)
	user := jsonQuote(piiUser)
	return []piiAPI{
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"m","messages":[{"role":"user","content":` + user + `}]}`,
			upstream: okUpstream},
		{name: "chat stream", path: "/v1/chat/completions",
			body:     `{"model":"m","stream":true,"messages":[{"role":"user","content":` + user + `}]}`,
			upstream: chatStream},
		{name: "messages", path: "/v1/messages", anthropic: true,
			body: `{"model":"claude-x","max_tokens":10,"messages":[{"role":"user","content":` + user + `}]}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
			}},
		{name: "messages stream", path: "/v1/messages", anthropic: true, upstream: msgStream,
			body: `{"model":"claude-x","max_tokens":10,"stream":true,"messages":[{"role":"user","content":` + user + `}]}`},
		{name: "responses", path: "/v1/responses", body: `{"model":"m","input":` + user + `}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem("ok"))) }},
		{name: "responses stream", path: "/v1/responses", body: `{"model":"m","stream":true,"input":` + user + `}`,
			upstream: streamingUpstream(responsesTextStream("ok")...)},
	}
}

// A rule on input.pii.count blocks or logs on the three APIs, stream or not,
// only when the org turned the check on. The audit row and the events carry
// kinds and counts, never the values.
func TestInputPIIRulesThroughGateway(t *testing.T) {
	for _, api := range piiAPIs() {
		for _, action := range []policy.Action{policy.ActionBlock, policy.ActionLog} {
			for _, on := range []bool{true, false} {
				name := api.name + "/" + string(action) + "/off"
				if on {
					name = api.name + "/" + string(action) + "/on"
				}
				t.Run(name, func(t *testing.T) {
					up := newFakeUpstream(t, api.upstream)
					r := rule(action, "input.pii.count", ">", 0)
					upURL := up.URL
					if api.anthropic {
						upURL = ""
					}
					h := startGateway(t, upURL, func(gw *gateway) {
						if api.anthropic {
							withAnthropic(up.URL)(gw)
						}
						withRules(r)(gw)
						gw.settings = piiOn(t, on)
					})
					resp, got := h.post(t, api.path, api.body, nil)
					row := h.oneRow(t)
					wantPII := outputguard.Counts{"email": 1, "phone": 1}
					switch {
					case on && action == policy.ActionBlock:
						if resp.StatusCode != 400 || up.hits.Load() != 0 {
							t.Errorf("got %d %s, upstream hits %d", resp.StatusCode, got, up.hits.Load())
						}
						if row.Action != actionBlock || row.Detected != layerPolicy || row.RuleID != r.ID {
							t.Errorf("row action %s detected %s rule %s", row.Action, row.Detected, row.RuleID)
						}
					case on:
						if resp.StatusCode != 200 || up.hits.Load() != 1 {
							t.Errorf("got %d %s, upstream hits %d", resp.StatusCode, got, up.hits.Load())
						}
						if row.Action != actionAllow || row.RuleID != r.ID {
							t.Errorf("row action %s rule %s", row.Action, row.RuleID)
						}
					default:
						wantPII = nil
						if resp.StatusCode != 200 || row.RuleID != uuid.Nil {
							t.Errorf("switch off: got %d, rule %s", resp.StatusCode, row.RuleID)
						}
					}
					if !maps.Equal(row.InputPII, wantPII) || (wantPII == nil) != (row.InputPII == nil) {
						t.Errorf("row pii = %v, want %v", row.InputPII, wantPII)
					}
					tags := auditTags(row)
					if on && (!slices.Contains(tags, "input:pii_email=1") || !slices.Contains(tags, "input:pii_phone=1")) {
						t.Errorf("tags = %v", tags)
					}
					noValues(t, "audit tags", tags...)
					for _, ev := range eventsFor(&row, 0.5) {
						for k, v := range ev.Attrs {
							if s, ok := v.(string); ok {
								noValues(t, "event attr "+k, s)
							}
						}
					}
					// The request still goes upstream unchanged: nothing is redacted.
					if resp.StatusCode == 200 {
						up.mu.Lock()
						sent := up.body
						up.mu.Unlock()
						if !strings.Contains(sent, "lan.nguyen@congty.vn") {
							t.Errorf("upstream got %s", sent)
						}
					}
				})
			}
		}
	}
}

// The setting is read per request, like every guard setting: turning it on
// or off applies to the next request without a restart.
func TestInputPIISettingReloads(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	var on bool
	h := startGateway(t, up.URL, func(gw *gateway) {
		withRules(rule(policy.ActionBlock, "input.pii.kinds", "contains", "email"))(gw)
		gw.settings = func(ctx context.Context, org uuid.UUID) (indirect.Settings, error) {
			return indirect.Settings{InputPII: &on}, nil
		}
	})
	body := chatBody(messages("user", piiUser), "")
	for _, step := range []struct {
		on     bool
		status int
	}{{false, 200}, {true, 400}, {false, 200}} {
		on = step.on
		if resp, got := h.post(t, "/v1/chat/completions", body, nil); resp.StatusCode != step.status {
			t.Errorf("input_pii %v: %d %s", step.on, resp.StatusCode, got)
		}
	}
}

// A request with no personal data passes a rule on the count, and a system
// prompt full of example data does not make it match.
func TestInputPIISystemPromptDoesNotCount(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		withRules(rule(policy.ActionBlock, "input.pii.count", ">", 0))(gw)
		gw.settings = piiOn(t, true)
		gw.scan = &scanConfig{Roles: allRoles, IndirectThreshold: indirect.BlockThreshold,
			IndirectAction: indirect.ActionBlock, History: historyLatest}
	})
	body := chatBody(messages("system", piiSystem, "user", "Summarise the meeting notes, version 2.1."), "")
	resp, got := h.post(t, "/v1/chat/completions", body, nil)
	if resp.StatusCode != 200 {
		t.Errorf("got %d %s", resp.StatusCode, got)
	}
	if row := h.oneRow(t); row.InputPII != nil {
		t.Errorf("pii = %v", row.InputPII)
	}
}

// Stored rules behave as before: one that names the removed pii.entities
// still reads [] when the check is on and the request carries personal data.
func TestInputPIIStoredRemovedFieldUnchanged(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		withRules(rule(policy.ActionBlock, "pii.entities", "contains", "email"),
			rule(policy.ActionBlock, "pii.entities", "contains", "EMAIL"))(gw)
		gw.settings = piiOn(t, true)
	})
	resp, got := h.post(t, "/v1/chat/completions", chatBody(messages("user", piiUser), ""), nil)
	if resp.StatusCode != 200 {
		t.Errorf("got %d %s", resp.StatusCode, got)
	}
	if row := h.oneRow(t); row.RuleID != uuid.Nil || row.InputPII["email"] != 1 {
		t.Errorf("row rule %s pii %v", row.RuleID, row.InputPII)
	}
}
