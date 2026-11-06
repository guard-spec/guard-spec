package outputguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// The Anthropic Messages API (/v1/messages). A response holds content blocks:
// text, thinking, redacted_thinking and tool_use (server_tool_use for the
// tools Anthropic runs). Text and thinking are guarded like the answer and
// the reasoning of a chat completion, tool inputs like tool-call arguments.
// A changed thinking block no longer matches its signature, so the upstream
// refuses it if the client sends it back in a later turn.

// MessagesResponse guards a complete (non-streaming) Messages API response.
// A content block of a type the guard does not know is refused
// (ErrUncheckable), as a content part that is not text is in a completion.
func (s *Scanner) MessagesResponse(body []byte, counts Counts) ([]byte, error) {
	doc, err := decodeObject(body)
	if err != nil {
		return nil, ErrNotJSON
	}
	if err := s.guardBlocks(doc["content"], counts); err != nil {
		return nil, err
	}
	return encode(doc)
}

func (s *Scanner) guardBlocks(raw any, counts Counts) error {
	if raw == nil {
		return nil
	}
	blocks, ok := raw.([]any)
	if !ok {
		return ErrUncheckable
	}
	for _, item := range blocks {
		b, ok := item.(map[string]any)
		if !ok {
			return ErrUncheckable
		}
		if err := s.guardBlock(b, counts); err != nil {
			return err
		}
	}
	return nil
}

// guardBlock rewrites one content block in place.
func (s *Scanner) guardBlock(b map[string]any, counts Counts) error {
	kind, _ := b["type"].(string)
	switch kind {
	case "text":
		text, ok := b["text"].(string)
		if !ok {
			return ErrUncheckable
		}
		b["text"] = s.Text(text, counts)
		s.guardCitations(b["citations"], counts)
	case "thinking":
		if s.g.cfg.DropReasoning {
			b["thinking"] = ""
			return nil
		}
		if text, ok := b["thinking"].(string); ok {
			b["thinking"] = s.Text(text, counts)
		}
	case "redacted_thinking":
		// Encrypted by the upstream: nothing a reader sees.
	case "tool_use", "server_tool_use":
		local := Counts{}
		if input, present := b["input"]; present {
			b["input"] = s.guardValue(input, local)
		}
		counts.add(local)
		if local[KindCanary] > 0 {
			return ErrToolCanary
		}
	default:
		return ErrUncheckable
	}
	return nil
}

// guardCitations guards the quoted text of a text block's citations.
func (s *Scanner) guardCitations(raw any, counts Counts) {
	list, _ := raw.([]any)
	for _, item := range list {
		if c, ok := item.(map[string]any); ok {
			if text, ok := c["cited_text"].(string); ok {
				c["cited_text"] = s.Text(text, counts)
			}
		}
	}
}

// MessageStream guards a Messages API event stream. Feed it the upstream bytes
// with Write and send what it returns. Each content block has its own Stream,
// so a pattern split across deltas is still caught; the text it holds back is
// sent as one more delta before the block's content_block_stop. Tool input
// arrives as pieces of JSON (input_json_delta), which are held whole and sent
// guarded as one delta when the block stops.
type MessageStream struct {
	s       *Scanner
	partial []byte
	lines   []string
	blocks  map[string]*messageBlock // by content block index
	order   []string
	whole   Counts // findings in the blocks of message_start
	// Counts holds what was acted on so far, including text still held.
	Counts  Counts
	blocked bool
	failed  bool
}

type messageBlock struct {
	kind   string  // text, thinking or tool
	text   *Stream // text and thinking
	input  strings.Builder
	counts Counts // tool input
	done   bool
}

// NewMessageStream returns a MessageStream for one response.
func (s *Scanner) NewMessageStream() *MessageStream {
	return &MessageStream{s: s, blocks: map[string]*messageBlock{}, whole: Counts{}, Counts: Counts{}}
}

// Blocked reports that the canary showed up, in block mode or in a tool's
// input. The caller must stop the stream; nothing after the event that leaked
// it is returned.
func (m *MessageStream) Blocked() bool { return m.blocked }

// Failed reports an event the guard cannot check, such as a content block of
// an unknown type. The caller must stop the stream; that event was not returned.
func (m *MessageStream) Failed() bool { return m.failed }

// Acted returns what was acted on so far.
func (m *MessageStream) Acted() Counts { return m.Counts }

func (m *MessageStream) stopped() bool { return m.blocked || m.failed }

// Write takes upstream bytes and returns the bytes to send, whole events only.
func (m *MessageStream) Write(p []byte) []byte {
	if m.stopped() {
		return nil
	}
	var out bytes.Buffer
	data := append(m.partial, p...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSuffix(string(data[:i]), "\r")
		data = data[i+1:]
		if line != "" {
			m.lines = append(m.lines, line)
			continue
		}
		if len(m.lines) == 0 {
			continue
		}
		event := m.event(m.lines)
		m.lines = nil
		if m.stopped() {
			m.partial = nil
			return out.Bytes()
		}
		out.Write(event)
	}
	m.partial = append([]byte(nil), data...)
	return out.Bytes()
}

// Close sends what the open blocks still hold, when the upstream ended without
// stopping them. A partial event the upstream left unfinished is dropped: it
// could not be checked.
func (m *MessageStream) Close() []byte {
	if m.stopped() {
		return nil
	}
	m.partial, m.lines = nil, nil
	var out bytes.Buffer
	for _, index := range m.order {
		if b := m.blocks[index]; !b.done {
			out.Write(m.finish(index, b))
			if m.stopped() {
				return nil
			}
		}
	}
	m.collect()
	if m.stopped() {
		return nil
	}
	return out.Bytes()
}

// event rewrites one event given as its lines.
func (m *MessageStream) event(lines []string) []byte {
	var data, other []string
	for _, line := range lines {
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		} else {
			other = append(other, line)
		}
	}
	raw := []byte(strings.Join(lines, "\n") + "\n\n")
	if len(data) == 0 {
		return raw
	}
	ev, err := decodeObject([]byte(strings.Join(data, "\n")))
	if err != nil {
		return raw // not JSON: no content to guard
	}
	var out []byte
	switch kind, _ := ev["type"].(string); kind {
	case "message_start":
		msg, _ := ev["message"].(map[string]any)
		if msg != nil {
			if err := m.s.guardBlocks(msg["content"], m.whole); err != nil {
				m.fail(err)
				return nil
			}
		}
		out = render(other, ev)
	case "content_block_start":
		out = m.start(other, ev)
	case "content_block_delta":
		out = m.delta(other, ev)
	case "content_block_stop":
		index := indexOf(ev)
		if b, ok := m.blocks[index]; ok && !b.done {
			out = m.finish(index, b)
		}
		if m.stopped() {
			return nil
		}
		out = append(out, raw...)
	default:
		// message_delta, message_stop, ping, error: no content.
		return raw
	}
	m.collect()
	if m.stopped() {
		return nil
	}
	return out
}

func (m *MessageStream) fail(err error) {
	if errors.Is(err, ErrToolCanary) {
		m.blocked = true
		return
	}
	m.failed = true
}

func (m *MessageStream) start(other []string, ev map[string]any) []byte {
	index := indexOf(ev)
	cb, ok := ev["content_block"].(map[string]any)
	if !ok {
		m.failed = true
		return nil
	}
	b := &messageBlock{counts: Counts{}}
	kind, _ := cb["type"].(string)
	switch kind {
	case "text", "thinking":
		// The field is named after the type: text or thinking.
		b.kind, b.text = kind, m.s.NewStream()
		if text, ok := cb[kind].(string); ok && text != "" {
			if kind == "thinking" && m.s.g.cfg.DropReasoning {
				cb[kind] = ""
			} else {
				cb[kind] = b.text.Write(text)
			}
		}
	case "redacted_thinking":
		b.kind, b.done = "redacted", true
	case "tool_use", "server_tool_use":
		b.kind = "tool"
		if input, present := cb["input"]; present {
			cb["input"] = m.s.guardValue(input, b.counts)
		}
		if b.counts[KindCanary] > 0 {
			m.blocked = true
			return nil
		}
	default:
		m.failed = true // a result block of a server tool, say: not checked
		return nil
	}
	if _, seen := m.blocks[index]; !seen {
		m.order = append(m.order, index)
	}
	m.blocks[index] = b
	return render(other, ev)
}

func (m *MessageStream) delta(other []string, ev map[string]any) []byte {
	index := indexOf(ev)
	b, ok := m.blocks[index]
	d, isMap := ev["delta"].(map[string]any)
	if !ok || !isMap || b.done {
		m.failed = true
		return nil
	}
	kind, _ := d["type"].(string)
	switch {
	case kind == "text_delta" && b.kind == "text", kind == "thinking_delta" && b.kind == "thinking":
		field := strings.TrimSuffix(kind, "_delta")
		text, ok := d[field].(string)
		if !ok {
			m.failed = true
			return nil
		}
		if b.kind == "thinking" && m.s.g.cfg.DropReasoning {
			return nil
		}
		out := b.text.Write(text)
		if out == "" {
			return nil // all of it is held back for now
		}
		d[field] = out
		return render(other, ev)
	case kind == "signature_delta" && b.kind == "thinking":
		// The signature closes the thinking: what is held goes out first.
		return append(m.flushText(index, b), render(other, ev)...)
	case kind == "input_json_delta" && b.kind == "tool":
		part, ok := d["partial_json"].(string)
		if !ok || b.input.Len()+len(part) > maxToolArgs {
			m.failed = true
			return nil
		}
		b.input.WriteString(part)
		return nil
	case kind == "citations_delta" && b.kind == "text":
		if c, ok := d["citation"].(map[string]any); ok {
			m.s.guardCitations([]any{c}, b.text.Counts)
		}
		return render(other, ev)
	}
	m.failed = true
	return nil
}

// finish returns the deltas a block still owes: its held text, or its whole
// guarded tool input.
func (m *MessageStream) finish(index string, b *messageBlock) []byte {
	b.done = true
	switch b.kind {
	case "text", "thinking":
		return m.flushText(index, b)
	case "tool":
		if b.input.Len() == 0 {
			return nil
		}
		guarded, leaked := m.s.Arguments(b.input.String(), b.counts)
		b.input.Reset()
		if leaked {
			m.blocked = true
			return nil
		}
		return deltaEvent(index, map[string]any{"type": "input_json_delta", "partial_json": guarded})
	}
	return nil
}

func (m *MessageStream) flushText(index string, b *messageBlock) []byte {
	rest := b.text.Flush()
	if rest == "" || (b.kind == "thinking" && m.s.g.cfg.DropReasoning) {
		return nil
	}
	if b.kind == "thinking" {
		return deltaEvent(index, map[string]any{"type": "thinking_delta", "thinking": rest})
	}
	return deltaEvent(index, map[string]any{"type": "text_delta", "text": rest})
}

// collect sums what every block has acted on and checks for a leaked canary.
func (m *MessageStream) collect() {
	total := Counts{}
	total.add(m.whole)
	for _, b := range m.blocks {
		total.add(b.counts)
		if b.text != nil {
			total.add(b.text.Counts)
		}
	}
	m.Counts = total
	if m.s.g.cfg.Canary == CanaryBlock && total[KindCanary] > 0 {
		m.blocked = true
	}
}

// jsonIndex writes a block index back as the upstream sent it.
func jsonIndex(index string) any {
	if _, err := strconv.Atoi(index); err == nil {
		return json.Number(index)
	}
	return index
}

func deltaEvent(index string, delta map[string]any) []byte {
	return render([]string{"event: content_block_delta"}, map[string]any{
		"type": "content_block_delta", "index": jsonIndex(index), "delta": delta})
}

// render writes an event: its non-data lines as they came, then the data.
func render(other []string, ev map[string]any) []byte {
	encoded, err := encode(ev)
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
