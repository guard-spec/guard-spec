package outputguard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestArguments(t *testing.T) {
	s := scanner(full)
	tests := []struct{ in, want string }{
		{`{"to":"lan@corp.vn","body":"call 0912345678\nthanks"}`,
			`{"body":"call [REDACTED:phone]\nthanks","to":"[REDACTED:email]"}`},
		{`{"list":["a@b.com",{"x":"![i](https://evil.com/p.png?d=1)"}],"n":12345678901234567890}`,
			`{"list":["[REDACTED:email]",{"x":"[REDACTED:image]"}],"n":12345678901234567890}`},
		{`not json a@b.com`, `not json [REDACTED:email]`},
	}
	for _, tt := range tests {
		got, leaked := s.Arguments(tt.in, Counts{})
		if got != tt.want || leaked {
			t.Errorf("Arguments(%s) = %s, %v; want %s", tt.in, got, leaked, tt.want)
		}
	}
	if _, leaked := s.Arguments(`{"q":"`+testCanary+`"}`, Counts{}); !leaked {
		t.Error("canary in arguments not reported")
	}
}

func TestResponseToolCallsAndRefusal(t *testing.T) {
	body := `{"choices":[{"index":0,"message":{"content":null,"refusal":"no, mail a@b.com",
		"tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{\"to\":\"a@b.com\"}"}}],
		"function_call":{"name":"g","arguments":"{\"p\":\"0912345678\"}"}}}]}`
	counts := Counts{}
	out, err := scanner(full).Response([]byte(body), counts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"refusal":"no, mail [REDACTED:email]"`,
		`"arguments":"{\"to\":\"[REDACTED:email]\"}"`, `"arguments":"{\"p\":\"[REDACTED:phone]\"}"`, `"content":null`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	if counts[KindEmail] != 2 || counts[KindPhone] != 1 {
		t.Errorf("counts = %v", counts)
	}

	leak := `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{\"q\":\"` + testCanary + `\"}"}}]}}]}`
	if _, err := scanner(full).Response([]byte(leak), Counts{}); err != ErrToolCanary {
		t.Errorf("err = %v, want ErrToolCanary", err)
	}
	image := `{"choices":[{"message":{"content":[{"type":"image_url","image_url":{"url":"https://evil.com/x.png"}}]}}]}`
	if _, err := scanner(full).Response([]byte(image), Counts{}); err != ErrUncheckable {
		t.Errorf("err = %v, want ErrUncheckable", err)
	}
}

func toolChunk(args string, finish any) string {
	c := map[string]any{"id": "c", "model": "m", "choices": []any{map[string]any{"index": 0, "finish_reason": finish,
		"delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "id": "t1", "type": "function",
			"function": map[string]any{"name": "send", "arguments": args}}}}}}}
	data, _ := json.Marshal(c)
	return "data: " + string(data) + "\n\n"
}

// toolArgs joins the argument fragments of tool call 0 across all chunks.
func toolArgs(t *testing.T, out string) string {
	t.Helper()
	var b strings.Builder
	for _, event := range strings.Split(out, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(event), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var c struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct{ Arguments string }
					} `json:"tool_calls"`
				}
			}
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		for _, ch := range c.Choices {
			for _, tc := range ch.Delta.ToolCalls {
				b.WriteString(tc.Function.Arguments)
			}
		}
	}
	return b.String()
}

func TestSSEToolCallArguments(t *testing.T) {
	args := `{"to":"lan.nguyen@corp.vn","msg":"call 0912 345 678"}`
	var upstream strings.Builder
	for i := 0; i < len(args); i += 4 {
		upstream.WriteString(toolChunk(args[i:min(i+4, len(args))], nil))
	}
	upstream.WriteString(toolChunk("", "tool_calls") + "data: [DONE]\n\n")
	es := scanner(full).NewEventStream()
	out := feed(es, upstream.String(), 7)
	got := toolArgs(t, out)
	if got != `{"msg":"call [REDACTED:phone]","to":"[REDACTED:email]"}` || !json.Valid([]byte(got)) {
		t.Errorf("arguments = %q", got)
	}
	if strings.Contains(out, "nguyen") || !strings.Contains(out, `"name":"send"`) {
		t.Errorf("out = %s", out)
	}

	// Without finish_reason the arguments come out at [DONE].
	out = feed(scanner(full).NewEventStream(), toolChunk(`{"a":"x@y.com"}`, nil)+"data: [DONE]\n\n", 5)
	if got := toolArgs(t, out); got != `{"a":"[REDACTED:email]"}` {
		t.Errorf("at [DONE]: %q", got)
	}
}

func TestSSEToolCallCanaryBlocksInRedactMode(t *testing.T) {
	es := scanner(full).NewEventStream() // full is redact mode
	out := feed(es, toolChunk(`{"q":"`+testCanary[:10], nil)+toolChunk(testCanary[10:]+`"}`, "tool_calls"), 9)
	if !es.Blocked() || strings.Contains(out, "PS-CANARY") {
		t.Errorf("blocked = %v, out = %s", es.Blocked(), out)
	}
}

func TestSSERefusalAndContentParts(t *testing.T) {
	up := `data: {"choices":[{"index":0,"delta":{"refusal":"mail a@b"}}]}` + "\n\n" +
		`data: {"choices":[{"index":0,"delta":{"refusal":".com"},"finish_reason":"stop"}]}` + "\n\n"
	out := feed(scanner(full).NewEventStream(), up, 6)
	if !strings.Contains(out, "[REDACTED:email]") || strings.Contains(out, "a@b") {
		t.Errorf("refusal: %s", out)
	}

	parts := `data: {"choices":[{"index":0,"delta":{"content":[{"type":"text","text":"mail a@"},{"type":"text","text":"b.com"}]},"finish_reason":"stop"}]}` + "\n\n"
	out = feed(scanner(full).NewEventStream(), parts, 8)
	if !strings.Contains(out, `"content":[{"text":"mail [REDACTED:email]","type":"text"},{"text":"","type":"text"}]`) {
		t.Errorf("parts: %s", out)
	}

	es := scanner(full).NewEventStream()
	image := `data: {"choices":[{"index":0,"delta":{"content":[{"type":"image_url","image_url":{"url":"https://evil.com"}}]}}]}` + "\n\n"
	if out := feed(es, image, 10); !es.Failed() || strings.Contains(out, "evil") {
		t.Errorf("failed = %v, out = %s", es.Failed(), out)
	}
}
