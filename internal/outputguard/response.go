package outputguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Text fields of a choice. content and text are the answer (chat and legacy
// completions); reasoning and reasoning_content are the thinking some upstreams
// (Ollama, vLLM) send next to it.
// refusal is the model's explanation when it declines (OpenAI).
var textFields = []string{"content", "text", "refusal", "reasoning", "reasoning_content"}

func isReasoning(field string) bool { return field == "reasoning" || field == "reasoning_content" }

var (
	// ErrNotJSON means a response body could not be parsed, so it cannot be checked.
	ErrNotJSON = errors.New("upstream response is not a JSON object")
	// ErrUncheckable means the response holds content the guard does not know
	// how to check, such as a content part that is not text.
	ErrUncheckable = errors.New("upstream response holds content the output guard cannot check")
	// ErrToolCanary means the canary showed up in tool-call arguments. Those
	// go to a program, not a reader, so the response is refused in any mode.
	ErrToolCanary = errors.New("canary leaked in tool-call arguments")
)

// Response guards a complete (non-streaming) completion body. It rewrites
// choices[].message.content (a string or text parts), refusal, tool-call
// arguments and the reasoning fields, and choices[].text.
func (s *Scanner) Response(body []byte, counts Counts) ([]byte, error) {
	doc, err := decodeObject(body)
	if err != nil {
		return nil, ErrNotJSON
	}
	choices, _ := doc["choices"].([]any)
	for _, raw := range choices {
		choice, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if msg, ok := choice["message"].(map[string]any); ok {
			if err := s.guardFields(msg, counts); err != nil {
				return nil, err
			}
			if err := s.guardToolCalls(msg, counts); err != nil {
				return nil, err
			}
		}
		if err := s.guardFields(choice, counts); err != nil { // legacy completions: choices[].text
			return nil, err
		}
	}
	return encode(doc)
}

// guardFields rewrites the text fields of m in place.
func (s *Scanner) guardFields(m map[string]any, counts Counts) error {
	for _, field := range textFields {
		v, present := m[field]
		if !present {
			continue
		}
		if isReasoning(field) && s.g.cfg.DropReasoning {
			delete(m, field)
			continue
		}
		switch val := v.(type) {
		case nil:
		case string:
			m[field] = s.Text(val, counts)
		case []any: // content parts
			for _, part := range val {
				p, ok := part.(map[string]any)
				if !ok {
					return ErrUncheckable
				}
				guarded := false
				for _, key := range []string{"text", "refusal"} {
					if text, ok := p[key].(string); ok {
						p[key] = s.Text(text, counts)
						guarded = true
					}
				}
				if !guarded {
					return ErrUncheckable // an image or audio part, say
				}
			}
		default:
			return ErrUncheckable
		}
	}
	return nil
}

// guardToolCalls rewrites message.tool_calls[].function.arguments and the
// older message.function_call.arguments.
func (s *Scanner) guardToolCalls(msg map[string]any, counts Counts) error {
	var functions []map[string]any
	if calls, ok := msg["tool_calls"].([]any); ok {
		for _, raw := range calls {
			if call, ok := raw.(map[string]any); ok {
				if fn, ok := call["function"].(map[string]any); ok {
					functions = append(functions, fn)
				}
			}
		}
	}
	if fn, ok := msg["function_call"].(map[string]any); ok {
		functions = append(functions, fn)
	}
	for _, fn := range functions {
		args, ok := fn["arguments"].(string)
		if !ok {
			continue
		}
		guarded, leaked := s.Arguments(args, counts)
		if leaked {
			return ErrToolCanary
		}
		fn["arguments"] = guarded
	}
	return nil
}

// Arguments guards tool-call arguments, a JSON text. Every string in it, keys
// included, is guarded on its own and the JSON is written back, so it stays
// valid. Arguments that are not JSON are guarded as plain text. leaked reports
// the canary.
func (s *Scanner) Arguments(args string, counts Counts) (guarded string, leaked bool) {
	local := Counts{}
	defer func() {
		counts.add(local)
		leaked = local[KindCanary] > 0
	}()
	dec := json.NewDecoder(strings.NewReader(args))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return s.Text(args, local), false
	}
	out, err := encode(s.guardValue(v, local))
	if err != nil {
		return s.Text(args, local), false
	}
	return string(out), false
}

func (s *Scanner) guardValue(v any, counts Counts) any {
	switch val := v.(type) {
	case string:
		return s.Text(val, counts)
	case []any:
		for i := range val {
			val[i] = s.guardValue(val[i], counts)
		}
		return val
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[s.Text(k, counts)] = s.guardValue(item, counts)
		}
		return out
	}
	return v
}

func decodeObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, ErrNotJSON
	}
	return doc, nil
}

// encode writes v without escaping <, > and &, so text reads as the model wrote it.
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// EventStream guards a server-sent event stream of completion chunks. Feed it
// the upstream bytes with Write and send what it returns. Each choice and text
// field has its own Stream, so a pattern split across chunks is still caught.
// Chunks keep their id, model and other fields; only the text changes.
type EventStream struct {
	s       *Scanner
	partial []byte   // a line not yet ended
	lines   []string // lines of the current event
	streams map[streamKey]*Stream
	order   []streamKey
	last    map[string]any // the latest chunk, as a template for a final one
	// Tool-call arguments are JSON, which a cut could leave invalid, so each
	// call's arguments are held whole and guarded when its choice finishes.
	tools      map[toolKey]*strings.Builder
	toolOrder  []toolKey
	toolCounts Counts
	// Counts holds what was acted on so far, including text still held.
	Counts  Counts
	blocked bool
	failed  bool
}

type toolKey struct {
	choice string // choices[].index
	index  string // delta.tool_calls[].index
}

// maxToolArgs bounds the arguments held for one tool call.
const maxToolArgs = 1 << 20

type streamKey struct {
	index string // choices[].index, as written by the upstream
	field string
	delta bool // the field sits in choices[].delta, not on the choice
}

// NewEventStream returns an EventStream for one response.
func (s *Scanner) NewEventStream() *EventStream {
	return &EventStream{s: s, streams: map[streamKey]*Stream{}, tools: map[toolKey]*strings.Builder{},
		toolCounts: Counts{}, Counts: Counts{}}
}

// Blocked reports that the canary showed up, in block mode or in tool-call
// arguments. The caller must stop the stream; nothing after the event that
// leaked it is returned.
func (e *EventStream) Blocked() bool { return e.blocked }

// Failed reports a chunk the guard cannot check, such as a content part that
// is not text. The caller must stop the stream; that chunk was not returned.
func (e *EventStream) Failed() bool { return e.failed }

func (e *EventStream) stopped() bool { return e.blocked || e.failed }

// Write takes upstream bytes and returns the bytes to send, whole events only.
func (e *EventStream) Write(p []byte) []byte {
	if e.stopped() {
		return nil
	}
	var out bytes.Buffer
	data := append(e.partial, p...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSuffix(string(data[:i]), "\r")
		data = data[i+1:]
		if line != "" {
			e.lines = append(e.lines, line)
			continue
		}
		if len(e.lines) == 0 {
			continue
		}
		event := e.event(e.lines)
		e.lines = nil
		if e.stopped() {
			e.partial = nil
			return out.Bytes()
		}
		out.Write(event)
	}
	e.partial = append([]byte(nil), data...)
	return out.Bytes()
}

// Close flushes the text still held, as one more chunk, when the upstream ended
// without [DONE]. A partial event the upstream left unfinished is dropped: it
// could not be checked.
func (e *EventStream) Close() []byte {
	if e.stopped() {
		return nil
	}
	e.partial, e.lines = nil, nil
	out := e.flushChunk()
	if e.stopped() {
		return nil
	}
	return out
}

// event rewrites one event given as its lines.
func (e *EventStream) event(lines []string) []byte {
	var data []string
	var other []string
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		default:
			other = append(other, line)
		}
	}
	raw := []byte(strings.Join(lines, "\n") + "\n\n")
	if len(data) == 0 {
		return raw
	}
	payload := strings.Join(data, "\n")
	if strings.TrimSpace(payload) == "[DONE]" {
		flushed := e.flushChunk()
		if e.stopped() {
			return nil
		}
		return append(flushed, raw...)
	}
	chunk, err := decodeObject([]byte(payload))
	if err != nil {
		return raw // not a completion chunk: nothing to guard
	}
	if _, ok := chunk["choices"]; !ok {
		return raw
	}
	e.rewriteChunk(chunk)
	if e.stopped() {
		return nil
	}
	encoded, err := encode(chunk)
	if err != nil {
		return nil
	}
	var b bytes.Buffer
	for _, line := range other {
		b.WriteString(line + "\n")
	}
	b.WriteString("data: ")
	b.Write(encoded)
	b.WriteString("\n\n")
	return b.Bytes()
}

func (e *EventStream) stream(key streamKey) *Stream {
	st, ok := e.streams[key]
	if !ok {
		st = e.s.NewStream()
		e.streams[key] = st
		e.order = append(e.order, key)
	}
	return st
}

// rewriteChunk guards the text of each choice and flushes a choice that finished.
func (e *EventStream) rewriteChunk(chunk map[string]any) {
	e.last = chunk
	choices, _ := chunk["choices"].([]any)
	for _, raw := range choices {
		choice, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		index := indexOf(choice)
		if delta, ok := choice["delta"].(map[string]any); ok {
			e.rewriteFields(delta, index, true)
			e.holdToolCalls(delta, index)
		}
		e.rewriteFields(choice, index, false)
		if e.failed {
			return
		}

		if reason, _ := choice["finish_reason"].(string); reason != "" {
			if calls := e.flushTools(index)[index]; len(calls) > 0 {
				delta, ok := choice["delta"].(map[string]any)
				if !ok {
					delta = map[string]any{}
					choice["delta"] = delta
				}
				prev, _ := delta["tool_calls"].([]any)
				delta["tool_calls"] = append(prev, calls...)
			}
			for _, key := range e.order {
				if key.index != index {
					continue
				}
				rest := e.streams[key].Flush()
				if rest == "" {
					continue
				}
				target := choice
				if key.delta {
					delta, ok := choice["delta"].(map[string]any)
					if !ok {
						delta = map[string]any{}
						choice["delta"] = delta
					}
					target = delta
				}
				if parts, ok := target[key.field].([]any); ok && len(parts) > 0 {
					first := parts[0].(map[string]any) // checked by rewriteFields
					first["text"] = first["text"].(string) + rest
					continue
				}
				prev, _ := target[key.field].(string)
				target[key.field] = prev + rest
			}
		}
	}
	e.collect()
}

func (e *EventStream) rewriteFields(m map[string]any, index string, delta bool) {
	for _, field := range textFields {
		v, present := m[field]
		if !present {
			continue
		}
		if isReasoning(field) && e.s.g.cfg.DropReasoning {
			delete(m, field)
			continue
		}
		st := e.stream(streamKey{index: index, field: field, delta: delta})
		switch val := v.(type) {
		case nil:
		case string:
			m[field] = st.Write(val)
		case []any:
			// Content parts: their text runs through the field's stream as one
			// text; what can be sent goes in the first part, the rest are emptied.
			var first map[string]any
			for _, part := range val {
				p, ok := part.(map[string]any)
				text, isText := p["text"].(string)
				if !ok || !isText {
					e.failed = true // not text: cannot be checked
					return
				}
				out := st.Write(text)
				p["text"] = ""
				if first == nil {
					first = p
				}
				first["text"] = first["text"].(string) + out
			}
		default:
			e.failed = true
			return
		}
	}
}

// holdToolCalls takes the argument fragments out of delta.tool_calls and holds
// them per call. The other fields (id, name, type) go on as they are.
func (e *EventStream) holdToolCalls(delta map[string]any, choice string) {
	calls, _ := delta["tool_calls"].([]any)
	for _, raw := range calls {
		call, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fn, ok := call["function"].(map[string]any)
		if !ok {
			continue
		}
		args, ok := fn["arguments"].(string)
		if !ok {
			continue
		}
		key := toolKey{choice: choice, index: indexOf(call)}
		b, ok := e.tools[key]
		if !ok {
			b = &strings.Builder{}
			e.tools[key] = b
			e.toolOrder = append(e.toolOrder, key)
		}
		if b.Len()+len(args) > maxToolArgs {
			e.failed = true
			return
		}
		b.WriteString(args)
		fn["arguments"] = ""
	}
}

// flushTools guards the held arguments of a choice's tool calls ("" for every
// choice) and returns them as tool_calls entries, per choice index.
func (e *EventStream) flushTools(choice string) map[string][]any {
	out := map[string][]any{}
	for _, key := range e.toolOrder {
		b := e.tools[key]
		if (choice != "" && key.choice != choice) || b == nil {
			continue
		}
		delete(e.tools, key)
		guarded, leaked := e.s.Arguments(b.String(), e.toolCounts)
		if leaked {
			e.blocked = true
			return nil
		}
		out[key.choice] = append(out[key.choice], map[string]any{"index": json.Number(key.index),
			"function": map[string]any{"arguments": guarded}})
	}
	return out
}

// collect sums what every stream has acted on and checks for a leaked canary.
func (e *EventStream) collect() {
	total := Counts{}
	for _, st := range e.streams {
		total.add(st.Counts)
	}
	total.add(e.toolCounts)
	e.Counts = total
	if e.s.g.cfg.Canary == CanaryBlock && total[KindCanary] > 0 {
		e.blocked = true
	}
}

// flushChunk returns one chunk with the text still held by every stream, built
// on the latest chunk so that it has the same id and model.
func (e *EventStream) flushChunk() []byte {
	byIndex := map[string]map[string]any{}
	var indexes []string
	for _, key := range e.order {
		rest := e.streams[key].Flush()
		if rest == "" {
			continue
		}
		choice, ok := byIndex[key.index]
		if !ok {
			choice = map[string]any{"index": json.Number(key.index), "finish_reason": nil}
			byIndex[key.index] = choice
			indexes = append(indexes, key.index)
		}
		target := choice
		if key.delta {
			delta, ok := choice["delta"].(map[string]any)
			if !ok {
				delta = map[string]any{}
				choice["delta"] = delta
			}
			target = delta
		}
		target[key.field] = rest
	}
	for choiceIndex, calls := range e.flushTools("") {
		choice, ok := byIndex[choiceIndex]
		if !ok {
			choice = map[string]any{"index": json.Number(choiceIndex), "finish_reason": nil}
			byIndex[choiceIndex] = choice
			indexes = append(indexes, choiceIndex)
		}
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			delta = map[string]any{}
			choice["delta"] = delta
		}
		delta["tool_calls"] = calls
	}
	e.collect()
	if len(indexes) == 0 || e.stopped() {
		return nil
	}
	sort.Strings(indexes)
	chunk := map[string]any{}
	for k, v := range e.last {
		if k != "choices" && k != "usage" {
			chunk[k] = v
		}
	}
	choices := make([]any, 0, len(indexes))
	for _, idx := range indexes {
		choices = append(choices, byIndex[idx])
	}
	chunk["choices"] = choices
	encoded, err := encode(chunk)
	if err != nil {
		return nil
	}
	return append(append([]byte("data: "), encoded...), '\n', '\n')
}

func indexOf(choice map[string]any) string {
	switch v := choice["index"].(type) {
	case json.Number:
		return v.String()
	case string:
		return v
	}
	return "0"
}
