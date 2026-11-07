// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func responsesScanner(mut func(*Config)) *Scanner {
	cfg := Config{RedactPII: true, Canary: CanaryBlock}
	if mut != nil {
		mut(&cfg)
	}
	return New(cfg).ForRequest(testCanary)
}

func responseBody(output string) string {
	return `{"id":"resp_1","object":"response","status":"completed","model":"m","instructions":"Be brief.\n\n` +
		CanaryNote(testCanary) + `","output":[` + output + `]}`
}

func decodeMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: %v", data, err)
	}
	return m
}

func TestResponsesResponseGuarded(t *testing.T) {
	s := responsesScanner(nil)
	counts := Counts{}
	out, err := s.ResponsesResponse([]byte(responseBody(`
		{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"Mail a@corp.vn later."}],"encrypted_content":"gAAAAenc"},
		{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[
		  {"type":"output_text","text":"Write to nguyen@corp.vn today.","logprobs":[{"token":"nguyen","logprob":-0.1}],
		   "annotations":[{"type":"url_citation","url":"https://example.com/a","title":"A","start_index":0,"end_index":5}]},
		  {"type":"output_text","text":"See the source.","annotations":[{"type":"url_citation","url":"https://example.com/b","title":"B","start_index":0,"end_index":3}],"logprobs":[]},
		  {"type":"refusal","refusal":"I cannot email b@corp.vn."}]},
		{"type":"function_call","id":"fc_1","call_id":"call_1","name":"send","arguments":"{\"to\":\"c@corp.vn\"}"},
		{"type":"custom_tool_call","id":"ct_1","call_id":"call_2","name":"run","input":"echo d@corp.vn"},
		{"type":"web_search_call","id":"ws_1","status":"completed","action":{"type":"search","query":"e@corp.vn"}}`)), counts)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, leaked := range []string{"a@corp.vn", "nguyen@corp.vn", "b@corp.vn", "c@corp.vn", "d@corp.vn", "e@corp.vn", testCanary} {
		if strings.Contains(text, leaked) {
			t.Errorf("%q left in %s", leaked, text)
		}
	}
	if counts[KindEmail] != 6 {
		t.Errorf("counts %v", counts)
	}
	doc := decodeMap(t, out)
	if doc["instructions"] != "Be brief." {
		t.Errorf("instructions %q", doc["instructions"])
	}
	output := doc["output"].([]any)
	if output[0].(map[string]any)["encrypted_content"] != "gAAAAenc" {
		t.Errorf("encrypted reasoning changed: %v", output[0])
	}
	parts := output[1].(map[string]any)["content"].([]any)
	changed, same := parts[0].(map[string]any), parts[1].(map[string]any)
	if len(changed["annotations"].([]any)) != 0 || len(changed["logprobs"].([]any)) != 0 {
		t.Errorf("changed text kept offsets or logprobs: %v", changed)
	}
	if len(same["annotations"].([]any)) != 1 {
		t.Errorf("unchanged text lost its annotation: %v", same)
	}
}

func TestResponsesResponseToolCanary(t *testing.T) {
	for _, item := range []string{
		`{"type":"function_call","call_id":"c","name":"f","arguments":"{\"x\":\"` + testCanary + `\"}"}`,
		`{"type":"custom_tool_call","call_id":"c","name":"f","input":"` + testCanary + `"}`,
	} {
		// Even in redact mode: tool input goes to a program.
		s := responsesScanner(func(c *Config) { c.Canary = CanaryRedact })
		if _, err := s.ResponsesResponse([]byte(responseBody(item)), Counts{}); !errors.Is(err, ErrToolCanary) {
			t.Errorf("%s: err %v", item, err)
		}
	}
}

func TestResponsesResponseUnknownTypes(t *testing.T) {
	for _, output := range []string{
		`{"type":"image_generation_call","id":"ig_1","result":"iVBORw0KGgo="}`,
		`{"type":"message","role":"assistant","content":[{"type":"output_audio","data":"AAAA"}]}`,
	} {
		if _, err := responsesScanner(nil).ResponsesResponse([]byte(responseBody(output)), Counts{}); !errors.Is(err, ErrUncheckable) {
			t.Errorf("%s: err %v, want ErrUncheckable", output, err)
		}
		pass := responsesScanner(func(c *Config) { c.PassUnknownBlocks = true })
		if out, err := pass.ResponsesResponse([]byte(responseBody(output)), Counts{}); err != nil || !strings.Contains(string(out), "AAAA") && !strings.Contains(string(out), "iVBOR") {
			t.Errorf("pass: %s %v", out, err)
		}
	}
	if _, err := responsesScanner(nil).ResponsesResponse([]byte(`not json`), Counts{}); !errors.Is(err, ErrNotJSON) {
		t.Errorf("not JSON: %v", err)
	}
}

func TestResponsesResponseDropReasoning(t *testing.T) {
	s := responsesScanner(func(c *Config) { c.DropReasoning = true })
	out, err := s.ResponsesResponse([]byte(responseBody(
		`{"type":"reasoning","summary":[{"type":"summary_text","text":"secret plan"}],"content":[{"type":"reasoning_text","text":"raw thoughts"}],"encrypted_content":"enc"}`)), Counts{})
	if err != nil || strings.Contains(string(out), "secret plan") || strings.Contains(string(out), "raw thoughts") || !strings.Contains(string(out), `"enc"`) {
		t.Errorf("%s %v", out, err)
	}
}

func TestResponsesResponseCanaryInText(t *testing.T) {
	counts := Counts{}
	out, err := responsesScanner(func(c *Config) { c.Canary = CanaryRedact }).ResponsesResponse([]byte(responseBody(
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"the marker is `+testCanary+`","annotations":[]}]}`)), counts)
	if err != nil || strings.Contains(string(out), testCanary) || counts[KindCanary] != 1 {
		t.Errorf("%s %v %v", out, err, counts)
	}
}

// ── Streams ─────────────────────────────────────────────────────────────────

type respEvent struct {
	Event string
	Data  map[string]any
}

func rsse(kind, data string) string { return "event: " + kind + "\ndata: " + data + "\n\n" }

func seqEvent(kind string, fields string) string {
	return rsse(kind, `{"type":"`+kind+`","sequence_number":0`+fields+`}`)
}

// feedResponses writes the events in small pieces and parses what comes out.
func feedResponses(t *testing.T, rs *ResponseStream, events ...string) []respEvent {
	t.Helper()
	var out strings.Builder
	for _, e := range events {
		for i := 0; i < len(e); i += 7 {
			out.Write(rs.Write([]byte(e[i:min(i+7, len(e))])))
		}
	}
	out.Write(rs.Close())
	var parsed []respEvent
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		if raw == "" {
			continue
		}
		var ev respEvent
		for _, line := range strings.Split(raw, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.Event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev.Data); err != nil {
					t.Fatalf("%q: %v", line, err)
				}
			}
		}
		if ev.Event != "" && ev.Data["type"] != ev.Event {
			t.Errorf("event %q carries type %v", ev.Event, ev.Data["type"])
		}
		parsed = append(parsed, ev)
	}
	return parsed
}

func textDeltas(text string, size int) []string {
	var out []string
	for i := 0; i < len(text); i += size {
		d, _ := json.Marshal(text[i:min(i+size, len(text))])
		out = append(out, seqEvent("response.output_text.delta",
			`,"item_id":"msg_1","output_index":0,"content_index":0,"delta":`+string(d)+`,"logprobs":[{"token":"x","logprob":0}]`))
	}
	return out
}

func messageStream(text string) []string {
	full, _ := json.Marshal(text)
	resp := `{"id":"resp_1","object":"response","status":"in_progress","instructions":"Be brief.\n\n` + CanaryNote(testCanary) + `","output":[]}`
	done := `{"id":"resp_1","object":"response","status":"completed","instructions":"Be brief.\n\n` + CanaryNote(testCanary) +
		`","output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":` +
		string(full) + `,"annotations":[{"type":"url_citation","url":"https://example.com/","title":"Ex","start_index":0,"end_index":3}]}]}]}`
	events := []string{
		seqEvent("response.created", `,"response":`+resp),
		seqEvent("response.in_progress", `,"response":`+resp),
		seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","status":"in_progress","content":[]}`),
		seqEvent("response.content_part.added", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}`),
	}
	events = append(events, textDeltas(text, 5)...)
	return append(events,
		seqEvent("response.output_text.annotation.added", `,"item_id":"msg_1","output_index":0,"content_index":0,"annotation_index":0,"annotation":{"type":"url_citation","url":"https://example.com/","title":"Ex","start_index":0,"end_index":3}`),
		seqEvent("response.output_text.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"text":`+string(full)+`,"logprobs":[]`),
		seqEvent("response.content_part.done", `,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":`+string(full)+`,"annotations":[{"type":"url_citation","url":"https://example.com/","title":"Ex","start_index":0,"end_index":3}]}`),
		seqEvent("response.output_item.done", `,"output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":`+string(full)+`,"annotations":[]}]}`),
		seqEvent("response.completed", `,"response":`+done),
	)
}

// streamedText checks that the deltas, the done events and the final response
// agree, and returns the text.
func streamedText(t *testing.T, events []respEvent) string {
	t.Helper()
	var deltas strings.Builder
	var done, part, item, final string
	seq := -1.0
	for _, ev := range events {
		n, ok := ev.Data["sequence_number"].(float64)
		if !ok || n != seq+1 {
			t.Errorf("%s: sequence_number %v after %v", ev.Event, ev.Data["sequence_number"], seq)
		}
		seq = n
		switch ev.Event {
		case "response.output_text.delta":
			deltas.WriteString(ev.Data["delta"].(string))
			if l := ev.Data["logprobs"].([]any); len(l) != 0 {
				t.Errorf("delta logprobs passed: %v", l)
			}
		case "response.output_text.done":
			done = ev.Data["text"].(string)
		case "response.content_part.done":
			part = ev.Data["part"].(map[string]any)["text"].(string)
		case "response.output_item.done":
			item = ev.Data["item"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
		case "response.completed":
			resp := ev.Data["response"].(map[string]any)
			if resp["instructions"] != "Be brief." {
				t.Errorf("canary note echoed: %v", resp["instructions"])
			}
			final = resp["output"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
		}
	}
	if deltas.String() != done || done != part || part != item || item != final {
		t.Errorf("texts differ:\ndeltas %q\ndone %q\npart %q\nitem %q\nfinal %q", deltas.String(), done, part, item, final)
	}
	return final
}

func countEvents(events []respEvent, kind string) int {
	n := 0
	for _, ev := range events {
		if ev.Event == kind {
			n++
		}
	}
	return n
}

func TestResponseStreamRedactsAcrossDeltas(t *testing.T) {
	rs := responsesScanner(nil).NewResponseStream()
	text := "Reach me at nguyen.van.a@corp.vn or call later. " + strings.Repeat("Filler words go here. ", 20)
	events := feedResponses(t, rs, messageStream(text)...)
	if rs.Failed() || rs.Blocked() {
		t.Fatalf("failed %v blocked %v", rs.Failed(), rs.Blocked())
	}
	got := streamedText(t, events)
	if strings.Contains(got, "nguyen.van.a@corp.vn") || !strings.Contains(got, "[REDACTED:email]") || rs.Acted()[KindEmail] != 1 {
		t.Errorf("got %q, acted %v", got, rs.Acted())
	}
	// The text changed, so the annotation with offsets is dropped everywhere.
	if n := countEvents(events, "response.output_text.annotation.added"); n != 0 {
		t.Errorf("%d annotation events", n)
	}
	for _, ev := range events {
		if ev.Event == "response.completed" {
			p := ev.Data["response"].(map[string]any)["output"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
			if len(p["annotations"].([]any)) != 0 {
				t.Errorf("final annotations %v", p["annotations"])
			}
		}
	}
}

func TestResponseStreamUnchangedKeepsAnnotations(t *testing.T) {
	rs := responsesScanner(nil).NewResponseStream()
	events := feedResponses(t, rs, messageStream("Rivers of Vietnam: the Red River and the Mekong.")...)
	streamedText(t, events)
	if n := countEvents(events, "response.output_text.annotation.added"); n != 1 {
		t.Errorf("%d annotation events", n)
	}
}

func TestResponseStreamCanaryBlocks(t *testing.T) {
	rs := responsesScanner(nil).NewResponseStream()
	events := feedResponses(t, rs, messageStream("the marker is "+testCanary+" and more text")...)
	if !rs.Blocked() {
		t.Fatal("not blocked")
	}
	if raw, _ := json.Marshal(events); strings.Contains(string(raw), testCanary) {
		t.Errorf("canary sent: %s", raw)
	}
	if countEvents(events, "response.completed") != 0 {
		t.Error("stream went on after the canary")
	}
	errEvent := string(rs.ErrorEvent("blocked", "invalid_request_error", "content_filter"))
	if !strings.Contains(errEvent, "event: error") || !strings.Contains(errEvent, `"code":"content_filter"`) ||
		!strings.Contains(errEvent, `"sequence_number"`) {
		t.Errorf("error event %q", errEvent)
	}
}

func functionCallStream(args string) []string {
	full, _ := json.Marshal(args)
	events := []string{
		seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"send","arguments":"","status":"in_progress"}`),
	}
	for i := 0; i < len(args); i += 4 {
		d, _ := json.Marshal(args[i:min(i+4, len(args))])
		events = append(events, seqEvent("response.function_call_arguments.delta", `,"item_id":"fc_1","output_index":0,"delta":`+string(d)))
	}
	return append(events,
		seqEvent("response.function_call_arguments.done", `,"item_id":"fc_1","output_index":0,"arguments":`+string(full)),
		seqEvent("response.output_item.done", `,"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"send","arguments":`+string(full)+`,"status":"completed"}`),
		seqEvent("response.completed", `,"response":{"id":"r","object":"response","status":"completed","output":[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"send","arguments":`+string(full)+`}]}`),
	)
}

func TestResponseStreamFunctionArguments(t *testing.T) {
	rs := responsesScanner(nil).NewResponseStream()
	events := feedResponses(t, rs, functionCallStream(`{"to":"nguyen@corp.vn","body":"hi"}`)...)
	if rs.Failed() || rs.Blocked() {
		t.Fatal("stopped")
	}
	var deltas []string
	var done, item, final string
	for _, ev := range events {
		switch ev.Event {
		case "response.function_call_arguments.delta":
			deltas = append(deltas, ev.Data["delta"].(string))
		case "response.function_call_arguments.done":
			done = ev.Data["arguments"].(string)
		case "response.output_item.done":
			item = ev.Data["item"].(map[string]any)["arguments"].(string)
		case "response.completed":
			final = ev.Data["response"].(map[string]any)["output"].([]any)[0].(map[string]any)["arguments"].(string)
		}
	}
	if len(deltas) != 1 || deltas[0] != done || done != item || item != final || strings.Contains(done, "nguyen@corp.vn") {
		t.Errorf("deltas %q done %q item %q final %q", deltas, done, item, final)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(done), &args); err != nil || args["body"] != "hi" {
		t.Errorf("arguments %q: %v", done, err)
	}

	rs = responsesScanner(func(c *Config) { c.Canary = CanaryRedact }).NewResponseStream()
	events = feedResponses(t, rs, functionCallStream(`{"to":"`+testCanary+`"}`)...)
	if !rs.Blocked() || countEvents(events, "response.function_call_arguments.delta") != 0 {
		t.Errorf("canary in arguments: blocked %v, events %v", rs.Blocked(), events)
	}
}

func TestResponseStreamUnknownItem(t *testing.T) {
	item := seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"image_generation_call","id":"ig_1","status":"in_progress"}`)
	partial := seqEvent("response.image_generation_call.partial_image", `,"output_index":0,"item_id":"ig_1","partial_image_b64":"iVBOR"`)
	rs := responsesScanner(nil).NewResponseStream()
	feedResponses(t, rs, item, partial)
	if !rs.Failed() {
		t.Error("unknown item passed")
	}
	rs = responsesScanner(func(c *Config) { c.PassUnknownBlocks = true }).NewResponseStream()
	events := feedResponses(t, rs, item, partial)
	if rs.Failed() || len(events) != 2 {
		t.Errorf("pass: failed %v, %d events", rs.Failed(), len(events))
	}
	// A progress event without content passes in either mode; one with
	// content of an unknown kind does not.
	rs = responsesScanner(nil).NewResponseStream()
	events = feedResponses(t, rs, seqEvent("response.web_search_call.searching", `,"output_index":0,"item_id":"ws_1"`))
	if rs.Failed() || len(events) != 1 {
		t.Errorf("progress event: failed %v", rs.Failed())
	}
	rs = responsesScanner(nil).NewResponseStream()
	feedResponses(t, rs, seqEvent("response.audio.transcript.delta", `,"delta":"secret"`))
	if !rs.Failed() {
		t.Error("unknown content event passed")
	}
}

func TestResponseStreamReasoning(t *testing.T) {
	events := []string{
		seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[]}`),
		seqEvent("response.reasoning_summary_part.added", `,"item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}`),
		seqEvent("response.reasoning_summary_text.delta", `,"item_id":"rs_1","output_index":0,"summary_index":0,"delta":"Plan: mail a@corp.vn"`),
		seqEvent("response.reasoning_summary_text.done", `,"item_id":"rs_1","output_index":0,"summary_index":0,"text":"Plan: mail a@corp.vn"`),
		seqEvent("response.reasoning_summary_part.done", `,"item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":"Plan: mail a@corp.vn"}`),
		seqEvent("response.output_item.done", `,"output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"Plan: mail a@corp.vn"}],"encrypted_content":"gAAA"}`),
	}
	rs := responsesScanner(nil).NewResponseStream()
	out := feedResponses(t, rs, events...)
	raw, _ := json.Marshal(out)
	if rs.Failed() || strings.Contains(string(raw), "a@corp.vn") || !strings.Contains(string(raw), "gAAA") ||
		!strings.Contains(string(raw), "Plan: mail [REDACTED:email]") {
		t.Errorf("guard: %s", raw)
	}
	rs = responsesScanner(func(c *Config) { c.DropReasoning = true }).NewResponseStream()
	out = feedResponses(t, rs, events...)
	raw, _ = json.Marshal(out)
	if rs.Failed() || strings.Contains(string(raw), "Plan") || countEvents(out, "response.reasoning_summary_text.delta") != 0 {
		t.Errorf("drop: %s", raw)
	}
}

func TestResponseStreamCloseFlushesHeldText(t *testing.T) {
	// The upstream ends without done events: what is held still goes out.
	rs := responsesScanner(nil).NewResponseStream()
	events := []string{
		seqEvent("response.output_item.added", `,"output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","content":[]}`),
	}
	events = append(events, textDeltas("short answer", 4)...)
	out := feedResponses(t, rs, events...)
	var text strings.Builder
	for _, ev := range out {
		if ev.Event == "response.output_text.delta" {
			text.WriteString(ev.Data["delta"].(string))
		}
	}
	if text.String() != "short answer" {
		t.Errorf("got %q", text.String())
	}
}
