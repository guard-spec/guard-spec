// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"strconv"
	"strings"
)

// Personal data kept from the upstream (RF-5b9b3aa2). The gateway replaces
// the personal data in request text before the request goes upstream:
//
//   - redact: with a label, "[EMAIL]"; the value is gone for good;
//   - tokenize: with a token, "⟦EMAIL_1⟧", the same token for the same value
//     within the request. The tokens are kept in memory for that request only,
//     and the answer has them replaced by the values again (Scanner.WithTokens)
//     before it reaches the client, streamed or not.
//
// The model only ever sees the label or the token. What it does with the
// token (repeats it, puts it in a tool call) comes back with the value, to
// the same client that sent it.

// Pseudonymization modes.
const (
	PIIOff      = "off"
	PIIRedact   = "redact"
	PIITokenize = "tokenize"
)

const (
	tokenOpen  = "⟦"
	tokenClose = "⟧"
	// maxTokenLen bounds how much text a stream holds back while it waits
	// for the end of something that may be a token: "⟦" and "⟧" (3 bytes each),
	// a kind and a number, with room for spaces the model may add.
	maxTokenLen = 40
)

// PIIMatch is one personal-data value in text: text[Start:End].
type PIIMatch struct {
	Kind       string
	Start, End int
}

// FindPII returns the personal data in text with the detectors and the
// overlap rule of CountPII, in order.
func FindPII(text string) []PIIMatch {
	var out []PIIMatch
	for _, m := range piiScanner.inlineMatches(text, 0) {
		out = append(out, PIIMatch{Kind: m.kind, Start: m.start, End: m.end})
	}
	return out
}

// Pseudonymizer replaces the personal data of one request. It is not safe
// for concurrent use.
type Pseudonymizer struct {
	mode  string
	kinds map[string]bool // nil: every kind
	// Counts is how many values of each kind were replaced.
	Counts Counts

	byValue map[string]string // kind + "\x00" + value -> token name
	byName  map[string]string // token name ("EMAIL_1") -> value
	next    map[string]int
}

// NewPseudonymizer returns a pseudonymizer for mode (PIIRedact or
// PIITokenize) and kinds (empty: every kind of PIIKinds); nil for PIIOff.
func NewPseudonymizer(mode string, kinds []string) *Pseudonymizer {
	if mode != PIIRedact && mode != PIITokenize {
		return nil
	}
	p := &Pseudonymizer{mode: mode, Counts: Counts{}}
	if len(kinds) > 0 {
		p.kinds = map[string]bool{}
		for _, k := range kinds {
			p.kinds[k] = true
		}
	}
	return p
}

// Apply returns text with the personal data of the selected kinds replaced.
func (p *Pseudonymizer) Apply(text string) string {
	matches := FindPII(text)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		if p.kinds != nil && !p.kinds[m.Kind] {
			continue
		}
		b.WriteString(text[last:m.Start])
		b.WriteString(p.replacement(m.Kind, text[m.Start:m.End]))
		p.Counts[m.Kind]++
		last = m.End
	}
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

func (p *Pseudonymizer) replacement(kind, value string) string {
	label := strings.ToUpper(kind)
	if p.mode == PIIRedact {
		return "[" + label + "]"
	}
	if p.byValue == nil {
		p.byValue, p.byName, p.next = map[string]string{}, map[string]string{}, map[string]int{}
	}
	key := kind + "\x00" + value
	name, ok := p.byValue[key]
	if !ok {
		p.next[kind]++
		name = label + "_" + strconv.Itoa(p.next[kind])
		p.byValue[key] = name
		p.byName[name] = value
	}
	return tokenOpen + name + tokenClose
}

// Tokens returns what the answer's tokens stand for, or nil when nothing was
// tokenized.
func (p *Pseudonymizer) Tokens() *Tokens {
	if p == nil || len(p.byName) == 0 {
		return nil
	}
	return &Tokens{byName: p.byName}
}

// Tokens maps the tokens of one request back to their values.
type Tokens struct {
	byName map[string]string
}

// lookup returns the value of a token's inside ("EMAIL_1"), tolerating case
// and the spaces a model may put in.
func (t *Tokens) lookup(inner string) (string, bool) {
	name := strings.ToUpper(strings.Join(strings.Fields(inner), ""))
	v, ok := t.byName[name]
	return v, ok
}

// Restore replaces every known token in a complete text.
func (t *Tokens) Restore(text string) string {
	var r restorer
	return r.write(text, t) + r.flush()
}

// restorer replaces tokens in a stream of text, holding back a tail that may
// be the start of a token split across writes.
type restorer struct {
	held string
}

func (r *restorer) write(text string, t *Tokens) string {
	s := r.held + text
	r.held = ""
	if !strings.Contains(s, tokenOpen) {
		return r.holdPartialOpen(s)
	}
	var b strings.Builder
	for {
		i := strings.Index(s, tokenOpen)
		if i < 0 {
			b.WriteString(r.holdPartialOpen(s))
			return b.String()
		}
		b.WriteString(s[:i])
		s = s[i:]
		j := strings.Index(s[len(tokenOpen):], tokenClose)
		if j < 0 {
			if len(s) < maxTokenLen {
				r.held = s // may be completed by the next write
				return b.String()
			}
			b.WriteString(tokenOpen)
			s = s[len(tokenOpen):]
			continue
		}
		inner := s[len(tokenOpen) : len(tokenOpen)+j]
		whole := len(tokenOpen) + j + len(tokenClose)
		if v, ok := t.lookup(inner); ok && whole <= maxTokenLen {
			b.WriteString(v)
			s = s[whole:]
			continue
		}
		b.WriteString(tokenOpen)
		s = s[len(tokenOpen):]
	}
}

// holdPartialOpen returns s without a trailing first byte or two of "⟦"
// (a write that ends inside the character), which it holds.
func (r *restorer) holdPartialOpen(s string) string {
	for n := len(tokenOpen) - 1; n > 0; n-- {
		if strings.HasSuffix(s, tokenOpen[:n]) {
			r.held = s[len(s)-n:]
			return s[:len(s)-n]
		}
	}
	return s
}

func (r *restorer) flush() string {
	out := r.held
	r.held = ""
	return out
}

// WithTokens makes the scanner put the values back for t's tokens in
// everything it guards, before its own checks: a value the output guard
// would redact (OUTPUT_PII_REDACT, or the org's output_pii_action) is then
// redacted in the answer as usual.
func (s *Scanner) WithTokens(t *Tokens) *Scanner {
	s.tokens = t
	return s
}

// RestoreOnly returns a guard that only puts values back for tokens
// (Scanner.WithTokens): for a gateway whose output guard is off. It changes
// nothing else and passes every block and item on.
func RestoreOnly() *Guard {
	g := New(Config{PassUnknownBlocks: true})
	g.passthrough = true
	return g
}
