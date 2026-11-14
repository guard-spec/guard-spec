// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// The answer every upstream gives in these tests, and its values.
const (
	outPIIAnswer = "Mail an@congty.vn, call 0912 345 678, host 10.0.0.7 ok"
	outEmail     = "an@congty.vn"
	outPhone     = "0912 345 678"
	outIPv4      = "10.0.0.7"
)

// twoOrgLookup: the key "test" is devOrg's, "acme" is otherOrg's.
func twoOrgLookup(_ context.Context, keyHash string) (tenant.KeyInfo, error) {
	switch keyHash {
	case tenant.HashKey("test"):
		return tenant.KeyInfo{OrgID: devOrg}, nil
	case tenant.HashKey("acme"):
		return tenant.KeyInfo{OrgID: otherOrg}, nil
	}
	return tenant.KeyInfo{}, errors.New("unknown key")
}

// orgSettings returns each org's guard settings, parsed as the gateway does.
func orgSettings(t testing.TB, raw map[uuid.UUID]string) settingsLoader {
	t.Helper()
	parsed := map[uuid.UUID]indirect.Settings{}
	for org, r := range raw {
		s, err := indirect.ParseSettings([]byte(r))
		if err != nil {
			t.Fatal(err)
		}
		parsed[org] = s
	}
	return func(_ context.Context, org uuid.UUID) (indirect.Settings, error) { return parsed[org], nil }
}

// outPIIAPIs: the four APIs, whole and streamed in small pieces, all
// answering outPIIAnswer.
func outPIIAPIs() []piiAPI {
	var pieces []string
	for i := 0; i < len(outPIIAnswer); i += 4 {
		pieces = append(pieces, outPIIAnswer[i:min(i+4, len(outPIIAnswer))])
	}
	chatStream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		var b strings.Builder
		for _, p := range pieces {
			b.WriteString(sseChunk(p, nil))
		}
		b.WriteString(sseChunk("", "stop") + "data: [DONE]\n\n")
		_, _ = w.Write([]byte(b.String()))
	}
	legacyChunk := func(text string, finish any) string {
		data, _ := json.Marshal(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": "m",
			"choices": []any{map[string]any{"index": 0, "text": text, "finish_reason": finish}}})
		return "data: " + string(data) + "\n\n"
	}
	legacyStream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		var b strings.Builder
		for _, p := range pieces {
			b.WriteString(legacyChunk(p, nil))
		}
		b.WriteString(legacyChunk("", "stop") + "data: [DONE]\n\n")
		_, _ = w.Write([]byte(b.String()))
	}
	msgEvents := []string{
		sseEvent("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-x","usage":{"input_tokens":3,"output_tokens":1}}}`),
		sseEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
	}
	for _, p := range pieces {
		msgEvents = append(msgEvents, textDelta(p))
	}
	msgEvents = append(msgEvents,
		sseEvent("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`),
		sseEvent("message_stop", `{"type":"message_stop"}`))
	return []piiAPI{
		{name: "chat", path: "/v1/chat/completions", body: clean,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(jsonCompletion(outPIIAnswer)))
			}},
		{name: "chat stream", path: "/v1/chat/completions", upstream: chatStream,
			body: `{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "completions", path: "/v1/completions", body: `{"model":"m","prompt":"hello"}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"cmpl-1","object":"text_completion","model":"m","choices":[{"index":0,"finish_reason":"stop","text":` +
					jsonQuote(outPIIAnswer) + `}]}`))
			}},
		{name: "completions stream", path: "/v1/completions", body: `{"model":"m","stream":true,"prompt":"hello"}`,
			upstream: legacyStream},
		{name: "messages", path: "/v1/messages", anthropic: true,
			body: `{"model":"claude-x","max_tokens":10,"messages":[{"role":"user","content":"hello"}]}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				anthropicJSON(w, messageResponse(`{"type":"text","text":`+jsonQuote(outPIIAnswer)+`}`))
			}},
		{name: "messages stream", path: "/v1/messages", anthropic: true, upstream: streamingUpstream(msgEvents...),
			body: `{"model":"claude-x","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "responses", path: "/v1/responses", body: `{"model":"m","input":"hello"}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem(outPIIAnswer))) }},
		{name: "responses stream", path: "/v1/responses", body: `{"model":"m","stream":true,"input":"hello"}`,
			upstream: streamingUpstream(responsesTextStream(outPIIAnswer)...)},
	}
}

// answerText is the text the client got: the body itself, or the text
// deltas of a stream joined.
func answerText(body string, stream bool) string {
	if !stream {
		return body
	}
	var b strings.Builder
	b.WriteString(joinStreamText(body))
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Object  string
			Choices []struct{ Text string }
		}
		if json.Unmarshal([]byte(data), &ev) == nil && ev.Object == "text_completion" {
			for _, c := range ev.Choices {
				b.WriteString(c.Text)
			}
		}
	}
	return b.String()
}

// startOutPII starts a gateway for api whose two orgs have the settings
// given; output nil runs it with OUTPUT_GUARD=off.
func startOutPII(t *testing.T, api piiAPI, settings map[uuid.UUID]string, output *outputguard.Config) *harness {
	t.Helper()
	up := newFakeUpstream(t, api.upstream)
	upURL := up.URL
	if api.anthropic {
		upURL = ""
	}
	return startGatewayLookup(t, upURL, twoOrgLookup, func(gw *gateway) {
		if api.anthropic {
			withAnthropic(up.URL)(gw)
		}
		if settings != nil {
			gw.settings = orgSettings(t, settings)
		}
		gw.output = nil
		if output != nil {
			gw.output = outputguard.New(*output)
		}
	})
}

// ask sends api's request with key and returns the answer text.
func ask(t *testing.T, h *harness, api piiAPI, key string) string {
	t.Helper()
	resp, body := h.post(t, api.path, api.body, map[string]string{"x-api-key": key})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	return answerText(body, strings.Contains(api.body, `"stream":true`))
}

// wantValues checks which values the answer kept (true) or had redacted.
func wantValues(t *testing.T, who, text string, want map[string]bool) {
	t.Helper()
	markers := map[string]string{outEmail: "[REDACTED:email]", outPhone: "[REDACTED:phone]", outIPv4: "[REDACTED:ipv4]"}
	for value, kept := range want {
		if strings.Contains(text, value) != kept || strings.Contains(text, markers[value]) == kept {
			t.Errorf("%s: %q kept=%v, got %q", who, value, kept, text)
		}
	}
}

// The gateway's default: e-mail and phone redacted, IPv4 kept.
var gatewayDefault = map[string]bool{outEmail: false, outPhone: false, outIPv4: true}

// Without output_pii_action and output_pii_kinds an org is guarded as in
// v0.7.0, with no settings, empty settings or other settings.
func TestOutputPIIUnsetIsGatewayDefault(t *testing.T) {
	def := defaultOutputConfig()
	for _, api := range outPIIAPIs() {
		for name, settings := range map[string]map[uuid.UUID]string{
			"no loader":      nil,
			"empty":          {devOrg: `{}`},
			"other settings": {devOrg: `{"input_pii_action":"redact","spotlight":"datamark"}`},
		} {
			t.Run(api.name+"/"+name, func(t *testing.T) {
				h := startOutPII(t, api, settings, &def)
				wantValues(t, "org", ask(t, h, api, "test"), gatewayDefault)
			})
		}
	}
}

// Two orgs on one gateway get their own redaction, streamed or not, on the
// four APIs; a third setting turns IPv4 on through the kinds.
func TestOutputPIIPerOrg(t *testing.T) {
	def := defaultOutputConfig()
	settings := map[uuid.UUID]string{
		devOrg:   `{"output_pii_action":"off"}`,
		otherOrg: `{"output_pii_action":"redact","output_pii_kinds":["email","ipv4"]}`,
	}
	for _, api := range outPIIAPIs() {
		t.Run(api.name, func(t *testing.T) {
			h := startOutPII(t, api, settings, &def)
			wantValues(t, "off org", ask(t, h, api, "test"), map[string]bool{outEmail: true, outPhone: true, outIPv4: true})
			wantValues(t, "kinds org", ask(t, h, api, "acme"), map[string]bool{outEmail: false, outPhone: true, outIPv4: false})
		})
	}
}

// An org turns redaction on where the gateway has OUTPUT_PII_REDACT=false;
// with OUTPUT_GUARD=off it cannot, and the answer passes unchanged.
func TestOutputPIIGatewaySwitches(t *testing.T) {
	settings := map[uuid.UUID]string{devOrg: `{"output_pii_action":"redact"}`, otherOrg: `{}`}
	noPII := defaultOutputConfig()
	noPII.RedactPII = false
	for _, api := range outPIIAPIs() {
		t.Run(api.name+"/OUTPUT_PII_REDACT=false", func(t *testing.T) {
			h := startOutPII(t, api, settings, &noPII)
			wantValues(t, "redact org", ask(t, h, api, "test"), gatewayDefault)
			wantValues(t, "unset org", ask(t, h, api, "acme"), map[string]bool{outEmail: true, outPhone: true, outIPv4: true})
		})
		t.Run(api.name+"/OUTPUT_GUARD=off", func(t *testing.T) {
			h := startOutPII(t, api, settings, nil)
			if got := ask(t, h, api, "test"); !strings.Contains(got, outPIIAnswer) {
				t.Errorf("changed with the output guard off: %q", got)
			}
		})
	}
}

// input_pii_action tokenize with output_pii_action off: the answer still gets
// the values back for the tokens, and they are not redacted.
func TestOutputPIIOffStillRestoresTokens(t *testing.T) {
	def := defaultOutputConfig()
	for _, api := range tokenAPIs() {
		for _, out := range []string{"off", "redact"} {
			t.Run(api.name+"/"+out, func(t *testing.T) {
				up := newFakeUpstream(t, api.upstream)
				upURL := up.URL
				if api.anthropic {
					upURL = ""
				}
				h := startGateway(t, upURL, func(gw *gateway) {
					if api.anthropic {
						withAnthropic(up.URL)(gw)
					}
					gw.settings = piiActionOn(t, fmt.Sprintf(`{"input_pii_action":"tokenize","output_pii_action":%q}`, out))
					gw.output = outputguard.New(def)
				})
				resp, got := h.post(t, api.path, api.body, nil)
				if resp.StatusCode != 200 {
					t.Fatalf("status %d: %s", resp.StatusCode, got)
				}
				text := answerText(got, strings.Contains(api.body, `"stream":true`))
				if strings.Contains(text, "⟦") {
					t.Errorf("a token reached the client: %q", text)
				}
				restored := strings.Contains(text, restoredAnswer)
				if out == "off" && !restored {
					t.Errorf("values not given back: %q", text)
				}
				if out == "redact" && (restored || !strings.Contains(text, "[REDACTED:email]")) {
					t.Errorf("values given back unredacted: %q", text)
				}
			})
		}
	}
}

// Invalid values are refused with an error naming the field.
func TestParseOutputPIISettings(t *testing.T) {
	for bad, want := range map[string]string{
		`{"output_pii_action":"tokenize"}`: "output_pii_action must be off or redact",
		`{"output_pii_action":"mask"}`:     "output_pii_action must be off or redact",
		`{"output_pii_action":""}`:         "output_pii_action must be off or redact",
		`{"output_pii_kinds":["name"]}`:    `unknown output_pii_kinds entry "name"`,
		`{"output_pii_kinds":"email"}`:     "output_pii_kinds",
		`{"output_pii_redact":true}`:       "unknown field",
		`{"output_pii_action":true}`:       "output_pii_action",
	} {
		_, err := indirect.ParseSettings([]byte(bad))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", bad, err, want)
		}
	}
	s, err := indirect.ParseSettings([]byte(`{"output_pii_action":"redact","output_pii_kinds":["email","ipv4"]}`))
	if a, k := s.OutputPII(); err != nil || a != "redact" || fmt.Sprint(k) != "[email ipv4]" {
		t.Fatalf("%q %v %v", a, k, err)
	}
	if a, k := (indirect.Settings{}).OutputPII(); a != "" || k != nil {
		t.Errorf("unset: %q %v", a, k)
	}
}
