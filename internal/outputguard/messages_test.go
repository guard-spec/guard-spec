package outputguard

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sse(kind, data string) string { return "event: " + kind + "\ndata: " + data + "\n\n" }

func blockStart(index int, block string) string {
	return sse("content_block_start", `{"type":"content_block_start","index":`+itoa(index)+`,"content_block":`+block+`}`)
}

func blockDelta(index int, delta string) string {
	return sse("content_block_delta", `{"type":"content_block_delta","index":`+itoa(index)+`,"delta":`+delta+`}`)
}

func blockStop(index int) string {
	return sse("content_block_stop", `{"type":"content_block_stop","index":`+itoa(index)+`}`)
}

func itoa(i int) string { return string(rune('0' + i)) }

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

type msgEvent struct {
	kind  string
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		Signature   string `json:"signature"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

// feedMessages writes the events one byte at a time, as the worst split, and parses
// what comes out.
func feedMessages(t *testing.T, ms *MessageStream, events ...string) []msgEvent {
	t.Helper()
	var out strings.Builder
	for _, e := range events {
		for i := 0; i < len(e); i++ {
			out.Write(ms.Write([]byte{e[i]}))
		}
	}
	out.Write(ms.Close())
	var parsed []msgEvent
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		if raw == "" {
			continue
		}
		var ev msgEvent
		for _, line := range strings.Split(raw, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
					t.Fatalf("event %q: %v", raw, err)
				}
			}
		}
		if ev.kind != ev.Type {
			t.Errorf("event line %q, data type %q", ev.kind, ev.Type)
		}
		parsed = append(parsed, ev)
	}
	return parsed
}

func TestMessageStreamTextAndThinking(t *testing.T) {
	g := New(Config{RedactPII: true})
	ms := g.ForRequest("").NewMessageStream()
	events := feedMessages(t, ms,
		sse("message_start", `{"type":"message_start","message":{"id":"m","content":[]}}`),
		blockStart(0, `{"type":"thinking","thinking":""}`),
		blockDelta(0, `{"type":"thinking_delta","thinking":"user is bob@exa"}`),
		blockDelta(0, `{"type":"thinking_delta","thinking":"mple.com"}`),
		blockDelta(0, `{"type":"signature_delta","signature":"SIG"}`),
		blockStop(0),
		blockStart(1, `{"type":"text","text":""}`),
		blockDelta(1, `{"type":"text_delta","text":"call 0912 345 678 now"}`),
		blockStop(1),
		sse("message_stop", `{"type":"message_stop"}`),
	)
	var thinking, text, order []string
	for _, e := range events {
		order = append(order, e.Type+"/"+e.Delta.Type)
		thinking = append(thinking, e.Delta.Thinking)
		text = append(text, e.Delta.Text)
	}
	if got := strings.Join(thinking, ""); got != "user is [REDACTED:email]" {
		t.Errorf("thinking %q", got)
	}
	if got := strings.Join(text, ""); strings.Contains(got, "345") || !strings.Contains(got, "[REDACTED:phone]") {
		t.Errorf("text %q", got)
	}
	// The held thinking goes out before the signature, and every delta before its stop.
	want := "message_start/,content_block_start/,content_block_delta/thinking_delta,content_block_delta/signature_delta," +
		"content_block_stop/,content_block_start/,content_block_delta/text_delta,content_block_stop/,message_stop/"
	if got := strings.Join(order, ","); got != want {
		t.Errorf("order\n got %s\nwant %s", got, want)
	}
	if ms.Acted()[KindEmail] != 1 || ms.Acted()[KindPhone] != 1 || ms.Blocked() || ms.Failed() {
		t.Errorf("counts %v blocked %v failed %v", ms.Acted(), ms.Blocked(), ms.Failed())
	}
}

func TestMessageStreamDropReasoning(t *testing.T) {
	ms := New(Config{DropReasoning: true}).ForRequest("").NewMessageStream()
	events := feedMessages(t, ms,
		blockStart(0, `{"type":"thinking","thinking":""}`),
		blockDelta(0, `{"type":"thinking_delta","thinking":"secret plan"}`),
		blockDelta(0, `{"type":"signature_delta","signature":"SIG"}`),
		blockStop(0))
	for _, e := range events {
		if e.Delta.Thinking != "" {
			t.Errorf("thinking sent: %+v", e)
		}
	}
	if len(events) != 3 {
		t.Errorf("events %+v", events)
	}
}

func TestMessageStreamToolInput(t *testing.T) {
	ms := New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	events := feedMessages(t, ms,
		blockStart(0, `{"type":"tool_use","id":"t","name":"send","input":{}}`),
		blockDelta(0, `{"type":"input_json_delta","partial_json":"{\"to\": \"a@ex"}`),
		blockDelta(0, `{"type":"input_json_delta","partial_json":"ample.com\"}"}`),
		blockStop(0))
	if len(events) != 3 || events[1].Delta.PartialJSON != `{"to":"[REDACTED:email]"}` || events[2].Type != "content_block_stop" {
		t.Errorf("events %+v", events)
	}
}

func TestMessageStreamCanary(t *testing.T) {
	const canary = "PS-CANARY-0123456789ABCDEF01234567"
	ms := New(Config{Canary: CanaryBlock}).ForRequest(canary).NewMessageStream()
	events := feedMessages(t, ms, blockStart(0, `{"type":"text","text":""}`),
		blockDelta(0, `{"type":"text_delta","text":"marker `+canary[:10]+`"}`),
		blockDelta(0, `{"type":"text_delta","text":"`+canary[10:]+` done"}`),
		blockStop(0))
	if !ms.Blocked() {
		t.Error("not blocked")
	}
	for _, e := range events {
		if strings.Contains(e.Delta.Text, "CANARY") {
			t.Error("canary sent")
		}
	}
	// In a tool's input the canary blocks in any mode.
	ms = New(Config{Canary: CanaryRedact}).ForRequest(canary).NewMessageStream()
	feedMessages(t, ms, blockStart(0, `{"type":"tool_use","id":"t","name":"x","input":{}}`),
		blockDelta(0, `{"type":"input_json_delta","partial_json":`+jsonString(`{"n":"`+canary+`"}`)+`}`),
		blockStop(0))
	if !ms.Blocked() {
		t.Error("tool canary not blocked")
	}
}

func TestMessageStreamUncheckable(t *testing.T) {
	for name, events := range map[string][]string{
		"unknown block":     {blockStart(0, `{"type":"web_search_tool_result","content":[{"title":"x"}]}`)},
		"delta of no block": {blockDelta(3, `{"type":"text_delta","text":"x"}`)},
		"wrong delta type":  {blockStart(0, `{"type":"text","text":""}`), blockDelta(0, `{"type":"input_json_delta","partial_json":"{"}`)},
		"unknown delta":     {blockStart(0, `{"type":"text","text":""}`), blockDelta(0, `{"type":"mystery_delta"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			ms := New(Config{}).ForRequest("").NewMessageStream()
			feedMessages(t, ms, events...)
			if !ms.Failed() {
				t.Error("not failed")
			}
		})
	}
}

func TestMessageStreamCloseFlushes(t *testing.T) {
	ms := New(Config{RedactPII: true}).ForRequest("").NewMessageStream()
	events := feedMessages(t, ms, blockStart(0, `{"type":"text","text":""}`),
		blockDelta(0, `{"type":"text_delta","text":"short"}`)) // the upstream ended here
	if len(events) != 2 || events[1].Delta.Text != "short" {
		t.Errorf("events %+v", events)
	}
}

func TestMessagesResponse(t *testing.T) {
	s := New(Config{RedactPII: true}).ForRequest("")
	counts := Counts{}
	out, err := s.MessagesResponse([]byte(`{"type":"message","content":[
		{"type":"text","text":"mail a@example.com","citations":[{"type":"char_location","cited_text":"b@example.com"}]},
		{"type":"redacted_thinking","data":"ENC"},
		{"type":"tool_use","id":"t","name":"x","input":{"q":"c@example.com","n":1}}]}`), counts)
	if err != nil || strings.Contains(string(out), "@example.com") || counts[KindEmail] != 3 ||
		!strings.Contains(string(out), `"data":"ENC"`) || !strings.Contains(string(out), `"n":1`) {
		t.Errorf("%s %v %v", out, counts, err)
	}
	if _, err := s.MessagesResponse([]byte(`{"content":[{"type":"image","source":{}}]}`), Counts{}); !errors.Is(err, ErrUncheckable) {
		t.Errorf("image block: %v", err)
	}
	if _, err := s.MessagesResponse([]byte(`not json`), Counts{}); !errors.Is(err, ErrNotJSON) {
		t.Errorf("not json: %v", err)
	}
	const canary = "PS-CANARY-0123456789ABCDEF01234567"
	s = New(Config{Canary: CanaryRedact}).ForRequest(canary)
	if _, err := s.MessagesResponse([]byte(`{"content":[{"type":"tool_use","input":{"x":"`+canary+`"}}]}`), Counts{}); !errors.Is(err, ErrToolCanary) {
		t.Errorf("tool canary: %v", err)
	}
}
