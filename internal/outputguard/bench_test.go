package outputguard

import (
	"strings"
	"testing"
)

// Answers for the output guard benchmarks: a clean answer, and one with links,
// images and personal data to rewrite. `make bench` runs them.
var benchAnswers = []struct{ name, text string }{
	{"clean_2k", strings.Repeat("Banana bread needs ripe bananas, flour, sugar, eggs and butter. ", 32)},
	{"findings_2k", strings.Repeat("Mail a@example.com or call 0912 345 678, card 4111 1111 1111 1111, "+
		"see [docs](https://evil.example/x?d=1) and ![x](https://evil.example/p.png?q=secret). ", 12)},
}

func benchGuard() *Guard {
	return New(Config{LinkAllowlist: []string{"docs.example.com"}, RedactPII: true, RedactIPv4: true, Canary: CanaryRedact})
}

// BenchmarkOutputGuardText guards a whole (non-streamed) answer.
func BenchmarkOutputGuardText(b *testing.B) {
	g := benchGuard()
	for _, in := range benchAnswers {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.text)))
			b.ReportAllocs()
			for b.Loop() {
				counts := Counts{}
				_ = g.ForRequest("PS-CANARY-0123456789ABCDEF01234567").Text(in.text, counts)
			}
		})
	}
}

// BenchmarkOutputGuardStream guards the same answers sent as 16-byte deltas,
// the way a streamed completion arrives.
func BenchmarkOutputGuardStream(b *testing.B) {
	g := benchGuard()
	for _, in := range benchAnswers {
		var chunks []string
		for s := in.text; s != ""; {
			n := min(16, len(s))
			chunks, s = append(chunks, s[:n]), s[n:]
		}
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.text)))
			b.ReportAllocs()
			for b.Loop() {
				st := g.ForRequest("PS-CANARY-0123456789ABCDEF01234567").NewStream()
				for _, c := range chunks {
					_ = st.Write(c)
				}
				_ = st.Flush()
			}
		})
	}
}

// sseUpstream builds the upstream events of one answer sent as deltas, for
// each stream kind: a chat completion, a Messages API response and a Responses
// API response.
func sseUpstream(kind, text string, deltas []string) []string {
	var events []string
	switch kind {
	case "chat":
		for _, d := range deltas {
			events = append(events, `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",`+
				`"choices":[{"index":0,"delta":{"content":`+jsonString(d)+`},"finish_reason":null}]}`+"\n\n")
		}
		events = append(events, `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",`+
			`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\n", "data: [DONE]\n\n")
	case "messages":
		events = append(events, sse("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message",`+
			`"role":"assistant","model":"m","content":[],"stop_reason":null}}`),
			blockStart(0, `{"type":"text","text":""}`))
		for _, d := range deltas {
			events = append(events, blockDelta(0, `{"type":"text_delta","text":`+jsonString(d)+`}`))
		}
		events = append(events, blockStop(0),
			sse("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`),
			sse("message_stop", `{"type":"message_stop"}`))
	case "responses":
		full := jsonString(text)
		item := `{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":` +
			full + `,"annotations":[]}]}`
		events = append(events,
			seqEvent("response.created", `,"response":{"id":"resp_1","object":"response","status":"in_progress","output":[]}`),
			seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","status":"in_progress","content":[]}`),
			seqEvent("response.content_part.added", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}`))
		for _, d := range deltas {
			events = append(events, seqEvent("response.output_text.delta",
				`,"item_id":"msg_1","output_index":0,"content_index":0,"delta":`+jsonString(d)))
		}
		events = append(events,
			seqEvent("response.output_text.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"text":`+full),
			seqEvent("response.content_part.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":`+full+`,"annotations":[]}`),
			seqEvent("response.output_item.done", `,"output_index":0,"item":`+item),
			seqEvent("response.completed", `,"response":{"id":"resp_1","object":"response","status":"completed","output":[`+item+`]}`))
	}
	return events
}

func streamChunks(text string, n int) []string {
	var out []string
	for s := text; s != ""; {
		k := min(n, len(s))
		out, s = append(out, s[:k]), s[k:]
	}
	return out
}

// sseStream is what the three event streams have in common.
type sseStream interface {
	Write([]byte) []byte
	Close() []byte
}

var sseKinds = []struct {
	name string
	open func(*Scanner) sseStream
}{
	{"chat", func(s *Scanner) sseStream { return s.NewEventStream() }},
	{"messages", func(s *Scanner) sseStream { return s.NewMessageStream() }},
	{"responses", func(s *Scanner) sseStream { return s.NewResponseStream() }},
}

// BenchmarkOutputGuardSSE guards the same answers as server-sent event streams
// of 16-byte deltas, for each stream kind, with the JSON decoding and encoding
// of every event.
func BenchmarkOutputGuardSSE(b *testing.B) {
	g := benchGuard()
	for _, k := range sseKinds {
		for _, in := range benchAnswers {
			var events [][]byte
			for _, e := range sseUpstream(k.name, in.text, streamChunks(in.text, 16)) {
				events = append(events, []byte(e))
			}
			b.Run(k.name+"/"+in.name, func(b *testing.B) {
				b.SetBytes(int64(len(in.text)))
				b.ReportAllocs()
				for b.Loop() {
					w := k.open(g.ForRequest("PS-CANARY-0123456789ABCDEF01234567"))
					for _, e := range events {
						_ = w.Write(e)
					}
					_ = w.Close()
				}
			})
		}
	}
}
