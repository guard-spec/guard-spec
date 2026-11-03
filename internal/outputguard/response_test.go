package outputguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func chunk(id string, index int, field, text string, finish any) string {
	delta := map[string]any{field: text}
	c := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": 1730000000, "model": "qwen3:4b",
		"system_fingerprint": "fp_ollama",
		"choices":            []any{map[string]any{"index": index, "delta": delta, "finish_reason": finish}},
	}
	data, _ := json.Marshal(c)
	return "data: " + string(data) + "\n\n"
}

// sseText collects the text of field from every chunk, per choice index.
func sseText(t *testing.T, stream, field string) (map[int]string, []map[string]any) {
	t.Helper()
	texts := map[int]string{}
	var chunks []map[string]any
	for _, event := range strings.Split(stream, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(event), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var c map[string]any
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatalf("bad event %q: %v", data, err)
		}
		chunks = append(chunks, c)
		for _, raw := range c["choices"].([]any) {
			choice := raw.(map[string]any)
			idx := int(choice["index"].(float64))
			if delta, ok := choice["delta"].(map[string]any); ok {
				if s, ok := delta[field].(string); ok {
					texts[idx] += s
				}
			}
		}
	}
	return texts, chunks
}

// feed writes the upstream bytes in pieces of n.
func feed(es *EventStream, upstream string, n int) string {
	var b strings.Builder
	for i := 0; i < len(upstream); i += n {
		end := i + n
		if end > len(upstream) {
			end = len(upstream)
		}
		b.Write(es.Write([]byte(upstream[i:end])))
	}
	b.Write(es.Close())
	return b.String()
}

func TestSSEPatternSplitAcrossChunks(t *testing.T) {
	pieces := []string{"Contact ", "nguyen", "@exam", "ple.com or 09", "12 345 ", "678. ![x](https://e", "vil.com/a.png?d=s", "ecret) bye"}
	var upstream strings.Builder
	for i, p := range pieces {
		var finish any
		if i == len(pieces)-1 {
			finish = "stop"
		}
		upstream.WriteString(chunk("chatcmpl-1", 0, "content", p, finish))
	}
	upstream.WriteString("data: [DONE]\n\n")

	for _, n := range []int{1, 7, 64, upstream.Len()} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			es := scanner(full).NewEventStream()
			out := feed(es, upstream.String(), n)
			texts, chunks := sseText(t, out, "content")
			want := "Contact [REDACTED:email] or [REDACTED:phone]. [REDACTED:image] bye"
			if texts[0] != want {
				t.Errorf("text = %q, want %q", texts[0], want)
			}
			if strings.Contains(out, "secret") || strings.Contains(out, "nguyen") {
				t.Errorf("leaked: %s", out)
			}
			for _, c := range chunks {
				if c["id"] != "chatcmpl-1" || c["model"] != "qwen3:4b" || c["system_fingerprint"] != "fp_ollama" ||
					c["object"] != "chat.completion.chunk" || c["created"] != float64(1730000000) {
					t.Errorf("chunk fields changed: %v", c)
				}
			}
			last := chunks[len(chunks)-1]["choices"].([]any)[0].(map[string]any)
			if last["finish_reason"] != "stop" {
				t.Errorf("last chunk = %v", last)
			}
			if !strings.HasSuffix(out, "data: [DONE]\n\n") {
				t.Errorf("no [DONE] at the end: %q", out)
			}
			if es.Counts[KindEmail] != 1 || es.Counts[KindPhone] != 1 || es.Counts[KindImage] != 1 {
				t.Errorf("counts = %v", es.Counts)
			}
		})
	}
}

func TestSSEFlushesAtDoneWithoutFinishReason(t *testing.T) {
	upstream := chunk("c", 0, "content", "mail a@b.com", nil) + "data: [DONE]\n\n"
	out := feed(scanner(full).NewEventStream(), upstream, 5)
	texts, chunks := sseText(t, out, "content")
	if texts[0] != "mail [REDACTED:email]" {
		t.Errorf("text = %q", texts[0])
	}
	if chunks[len(chunks)-1]["id"] != "c" {
		t.Errorf("flush chunk lost the id: %v", chunks[len(chunks)-1])
	}
}

func TestSSEFlushesAtEOF(t *testing.T) {
	out := feed(scanner(full).NewEventStream(), chunk("c", 0, "content", "call 0912345678", nil), 3)
	if texts, _ := sseText(t, out, "content"); texts[0] != "call [REDACTED:phone]" {
		t.Errorf("text = %q", texts[0])
	}
}

func TestSSEChoicesAreSeparate(t *testing.T) {
	upstream := chunk("c", 0, "content", "a@b", nil) + chunk("c", 1, "content", "x@y.com", nil) +
		chunk("c", 0, "content", ".com", "stop") + chunk("c", 1, "content", "", "stop") + "data: [DONE]\n\n"
	out := feed(scanner(full).NewEventStream(), upstream, 9)
	texts, _ := sseText(t, out, "content")
	if texts[0] != "[REDACTED:email]" || texts[1] != "[REDACTED:email]" {
		t.Errorf("texts = %v", texts)
	}
}

func TestSSEReasoning(t *testing.T) {
	upstream := chunk("c", 0, "reasoning", "the user is a@b.com", nil) +
		chunk("c", 0, "content", "hello", "stop") + "data: [DONE]\n\n"

	out := feed(scanner(full).NewEventStream(), upstream, 4)
	if texts, _ := sseText(t, out, "reasoning"); texts[0] != "the user is [REDACTED:email]" {
		t.Errorf("guarded reasoning = %q", texts[0])
	}

	cfg := full
	cfg.DropReasoning = true
	out = feed(scanner(cfg).NewEventStream(), upstream, 4)
	if strings.Contains(out, "reasoning") || strings.Contains(out, "user is") {
		t.Errorf("reasoning not dropped: %s", out)
	}
	if texts, _ := sseText(t, out, "content"); texts[0] != "hello" {
		t.Errorf("content = %q", texts[0])
	}
}

func TestSSECanaryBlock(t *testing.T) {
	cfg := full
	cfg.Canary = CanaryBlock
	upstream := chunk("c", 0, "content", "safe start. ", nil) +
		chunk("c", 0, "content", "PS-CANARY-0123456789AB", nil) +
		chunk("c", 0, "content", "CDEF01234567 more", "stop") + "data: [DONE]\n\n"
	es := scanner(cfg).NewEventStream()
	out := feed(es, upstream, 11)
	if !es.Blocked() || es.Counts[KindCanary] != 1 {
		t.Fatalf("blocked = %v, counts = %v", es.Blocked(), es.Counts)
	}
	if strings.Contains(out, "PS-CANARY") || strings.Contains(out, "[DONE]") {
		t.Errorf("leaked after block: %q", out)
	}
}

func TestSSECanaryRedact(t *testing.T) {
	upstream := chunk("c", 0, "content", "x PS-CANARY-0123456789AB", nil) +
		chunk("c", 0, "content", "CDEF01234567 y", "stop") + "data: [DONE]\n\n"
	es := scanner(full).NewEventStream()
	out := feed(es, upstream, 6)
	if texts, _ := sseText(t, out, "content"); texts[0] != "x [REDACTED:canary] y" {
		t.Errorf("text = %q", texts[0])
	}
	if es.Blocked() || es.Counts[KindCanary] != 1 {
		t.Errorf("blocked = %v, counts = %v", es.Blocked(), es.Counts)
	}
}

func TestSSEPassesOtherEvents(t *testing.T) {
	upstream := ": keep-alive\n\nevent: ping\ndata: hello\n\ndata: {\"object\":\"x\"}\n\n"
	out := feed(scanner(full).NewEventStream(), upstream, 3)
	if out != upstream {
		t.Errorf("got %q", out)
	}
}

func TestSSEDropsUnfinishedEvent(t *testing.T) {
	out := feed(scanner(full).NewEventStream(), `data: {"choices":[{"delta":{"content":"a@b.c`, 4)
	if out != "" {
		t.Errorf("got %q", out)
	}
}

func TestSSELegacyCompletionText(t *testing.T) {
	upstream := `data: {"id":"c","choices":[{"index":0,"text":"mail a@b.com","finish_reason":"stop"}]}` + "\n\n"
	out := feed(scanner(full).NewEventStream(), upstream, 5)
	if !strings.Contains(out, `"text":"mail [REDACTED:email]"`) {
		t.Errorf("got %q", out)
	}
}

func TestResponse(t *testing.T) {
	body := `{"id":"chatcmpl-9","object":"chat.completion","model":"m","usage":{"total_tokens":12345678901234567890},
	"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant",
	"content":"see ![a](https://evil.com/x.png?q=1) or mail a@b.com <b>ok</b>","reasoning":"call 0912345678"}}]}`
	counts := Counts{}
	out, err := scanner(full).Response([]byte(body), counts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ID      string
		Usage   map[string]json.Number
		Choices []struct {
			Message map[string]string
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	msg := doc.Choices[0].Message
	if msg["content"] != "see [REDACTED:image] or mail [REDACTED:email] <b>ok</b>" ||
		msg["reasoning"] != "call [REDACTED:phone]" || msg["role"] != "assistant" {
		t.Errorf("message = %v", msg)
	}
	if doc.ID != "chatcmpl-9" || doc.Usage["total_tokens"] != "12345678901234567890" {
		t.Errorf("fields changed: %s", out)
	}
	if counts[KindImage] != 1 || counts[KindEmail] != 1 || counts[KindPhone] != 1 {
		t.Errorf("counts = %v", counts)
	}

	cfg := full
	cfg.DropReasoning = true
	out, _ = scanner(cfg).Response([]byte(body), Counts{})
	if strings.Contains(string(out), "reasoning") {
		t.Errorf("reasoning kept: %s", out)
	}

	if _, err := scanner(full).Response([]byte("not json"), Counts{}); err == nil {
		t.Error("accepted a body it cannot check")
	}
}
