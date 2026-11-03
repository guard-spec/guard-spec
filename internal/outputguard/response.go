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
var textFields = []string{"content", "text", "reasoning", "reasoning_content"}

func isReasoning(field string) bool { return field == "reasoning" || field == "reasoning_content" }

// ErrNotJSON means a response body could not be parsed, so it cannot be checked.
var ErrNotJSON = errors.New("upstream response is not a JSON object")

// Response guards a complete (non-streaming) completion body. It rewrites
// choices[].message.content and choices[].text, and the reasoning fields.
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
			s.guardFields(msg, counts)
		}
		s.guardFields(choice, counts) // legacy completions: choices[].text
	}
	return encode(doc)
}

// guardFields rewrites the text fields of m in place.
func (s *Scanner) guardFields(m map[string]any, counts Counts) {
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
		case string:
			m[field] = s.Text(val, counts)
		case []any: // content parts
			for _, part := range val {
				if p, ok := part.(map[string]any); ok {
					if text, ok := p["text"].(string); ok {
						p["text"] = s.Text(text, counts)
					}
				}
			}
		}
	}
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
	// Counts holds what was acted on so far, including text still held.
	Counts  Counts
	blocked bool
}

type streamKey struct {
	index string // choices[].index, as written by the upstream
	field string
	delta bool // the field sits in choices[].delta, not on the choice
}

// NewEventStream returns an EventStream for one response.
func (s *Scanner) NewEventStream() *EventStream {
	return &EventStream{s: s, streams: map[streamKey]*Stream{}, Counts: Counts{}}
}

// Blocked reports that the canary showed up and the guard is in block mode.
// The caller must stop the stream; nothing after the event that leaked it is
// returned.
func (e *EventStream) Blocked() bool { return e.blocked }

// Write takes upstream bytes and returns the bytes to send, whole events only.
func (e *EventStream) Write(p []byte) []byte {
	if e.blocked {
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
		if e.blocked {
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
	if e.blocked {
		return nil
	}
	e.partial, e.lines = nil, nil
	out := e.flushChunk()
	if e.blocked {
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
		if e.blocked {
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
	if e.blocked {
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
		}
		e.rewriteFields(choice, index, false)

		if reason, _ := choice["finish_reason"].(string); reason != "" {
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
		text, ok := v.(string)
		if !ok {
			continue
		}
		m[field] = e.stream(streamKey{index: index, field: field, delta: delta}).Write(text)
	}
}

// collect sums what every stream has acted on and checks for a leaked canary.
func (e *EventStream) collect() {
	total := Counts{}
	for _, st := range e.streams {
		total.add(st.Counts)
	}
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
	e.collect()
	if len(indexes) == 0 || e.blocked {
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
