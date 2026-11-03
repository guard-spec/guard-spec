// Package rules is the L1 v2 prompt-injection detector: weighted phrase and
// co-occurrence rules matched on the canonical skeleton of the text (see
// package skeleton), plus a few structural regexes matched on the original.
//
// A rule fires on a sequence of terms that occur in order, in one sentence,
// with at most Gap words between them: "ignore" + "previous" + "instructions",
// "bỏ qua" + "chỉ thị" + "trước đó". Single keywords never fire a rule on their
// own; they only add a small ranking score (at most 0.17).
//
// Hard-benign suppressors (general patterns, not eval sentences):
//   - meta: the match sits in a sentence that asks about or discusses
//     attacks ("what is prompt injection", "how do attackers ...", a
//     security training or pentest report) → weight × 0.4;
//   - quoted mention: the whole match is inside quotes and the text talks
//     about attacks or frames it as an example ("phrases like '...'") → × 0.4;
//   - code literal: the match is a string literal in code (test fixtures,
//     detector patterns) → × 0.3. Code comments are not suppressed, since
//     they carry indirect injection into coding assistants;
//   - negation: "never reveal ...", "không tiết lộ ..." weakens extraction
//     and exfiltration rules → × 0.3.
//
// Scoring:
//   - each fired rule has a weight w in (0,1), scaled by the suppressors;
//   - a category's score is the noisy-OR of its rules' weights;
//   - the text's score is the strongest rule plus the noisy-OR of the others
//     at half weight: 1 - (1-w_max) * prod(1 - w_i/2).
//
// The result names the top category and every fired rule id, so a block can
// be explained.
package rules

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/promptshield/promptshield/internal/inference/skeleton"
)

// Categories reported by the engine (the eval set uses the same names).
const (
	DirectInjection   = "direct_injection"
	IndirectInjection = "indirect_injection"
	Jailbreak         = "jailbreak"
	PromptExtraction  = "prompt_extraction"
	DataExfiltration  = "data_exfiltration"
	ToolPoisoning     = "tool_poisoning"
	Obfuscation       = "obfuscation"
)

// Result is the engine's verdict on one text.
type Result struct {
	Score      float64            // in [0,1]
	Category   string             // category of the strongest rule; "" when none fired
	Categories map[string]float64 // per-category scores (only categories that fired)
	Rules      []string           // ids of fired rules, strongest first
}

// Suppression factors for meta discussion.
const (
	metaFactor      = 0.4  // the match is in a sentence that asks about or discusses attacks
	quoteFactor     = 0.4  // the match is quoted in a text that mentions or discusses attacks
	codeQuoteFactor = 0.3  // a string literal in code
	baseScore       = 0.02 // no cue at all
	cueStep         = 0.03 // per distinct cue word, for ranking only
	maxCues         = 5
	maxDecodeLen    = 4096
)

// term is a set of alternative phrases. Each phrase is a sequence of word
// keys; a word ending in '*' matches any word with that prefix.
type term struct {
	id   int
	alts [][]word
}

type word struct {
	key    string
	prefix bool
}

// rule is a phrase rule.
type rule struct {
	id         string
	cat        string
	w          float64
	seq        []*term
	gap        int    // max words between consecutive terms
	anyOrder   bool   // two-term rules: accept the reverse order too
	crossSent  bool   // the terms may span sentences
	noSuppress bool   // meta-discussion suppressors do not apply
	needFlag   string // fires only when this flag rule matched
}

// flagRule is a regex on the lowercased original text. It fires as a rule
// (when w > 0) and raises a flag other rules can require.
type flagRule struct {
	id   string
	cat  string
	w    float64
	re   *regexp.Regexp
	flag string
}

// Engine holds compiled rules. It is safe for concurrent use.
type Engine struct {
	rules    []rule
	flags    []flagRule
	terms    []*term
	cues     map[string]bool // keys that add the small ranking score
	lexicon  map[string]bool // keys used to split glued words
	reversed map[string]bool // reversed keys that hint at reversed text
	meta     metaTerms
}

type metaTerms struct {
	question, topic, strongTopic, mention *term
	code                                  *regexp.Regexp
}

// token is one word of the skeleton.
type token struct {
	key    string
	sent   int
	quoted bool
}

type span struct{ start, end int } // token indexes, end exclusive

// doc is a tokenized text with per-call caches.
type doc struct {
	toks   []token
	index  map[string][]int
	flags  map[string]bool
	cache  map[int][]span
	isCode bool
}

// Score runs the engine on sanitized text.
func (e *Engine) Score(text string) Result {
	return e.score(text, 0)
}

func (e *Engine) score(text string, depth int) Result {
	text = strings.NewReplacer("[DATA]", "", "[/DATA]", "").Replace(text)
	an := skeleton.Analyze(text)
	d := e.tokenize(an.Text)
	d.flags = map[string]bool{}
	var hits []hit
	for i := range e.flags {
		f := &e.flags[i]
		if f.re.MatchString(an.Folded) {
			if f.flag != "" {
				d.flags[f.flag] = true
			}
			if f.w > 0 {
				hits = append(hits, hit{id: f.id, cat: f.cat, w: f.w})
			}
		}
	}
	d.isCode = e.meta.code.MatchString(text)
	hits = append(hits, e.matchRules(d)...)

	// Reversed text: only tried when a reversed rule word appears.
	if depth == 0 && e.hasReversedCue(d) {
		rev := e.score(reverse(text), depth+1)
		if rev.Score > 0.3 {
			hits = append(hits, hit{id: "obf.reversed", cat: Obfuscation, w: rev.Score * 0.95})
		}
	}
	// Base64 payloads: decode and score once.
	if depth == 0 {
		for _, dec := range decodeBase64(text) {
			sub := e.score(dec, depth+1)
			if sub.Score > 0.3 {
				hits = append(hits, hit{id: "obf.base64", cat: Obfuscation, w: sub.Score * 0.95})
			}
		}
	}
	// Obfuscation evidence: a rule fired on a text that needed folding.
	if len(hits) > 0 && an.Obfuscated() {
		best := 0.0
		for _, h := range hits {
			best = max(best, h.w)
		}
		if best >= 0.5 {
			hits = append(hits, hit{id: "obf.folded", cat: Obfuscation, w: min(0.9, best+0.05)})
		}
	}
	return e.combine(d, hits)
}

type hit struct {
	id  string
	cat string
	w   float64
}

func (e *Engine) combine(d *doc, hits []hit) Result {
	if len(hits) == 0 {
		cues := 0
		seen := map[string]bool{}
		for _, t := range d.toks {
			if e.cues[t.key] && !seen[t.key] {
				seen[t.key] = true
				cues++
			}
		}
		return Result{Score: baseScore + cueStep*float64(min(cues, maxCues))}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].w > hits[j].w })
	res := Result{Categories: map[string]float64{}, Category: hits[0].cat}
	rest := 1.0
	seen := map[string]bool{}
	for i, h := range hits {
		if !seen[h.id] {
			res.Rules = append(res.Rules, h.id)
			seen[h.id] = true
		} else {
			continue
		}
		c := res.Categories[h.cat]
		res.Categories[h.cat] = 1 - (1-c)*(1-h.w)
		if i > 0 {
			rest *= 1 - h.w/2
		}
	}
	res.Score = min(0.99, 1-(1-hits[0].w)*rest)
	for k, v := range res.Categories {
		res.Categories[k] = min(0.99, v)
	}
	return res
}

// matchRules evaluates every phrase rule and applies suppressors.
func (e *Engine) matchRules(d *doc) []hit {
	metaSent := map[int]bool{}
	anyMeta := false
	for _, t := range []*term{e.meta.strongTopic} {
		for _, s := range e.find(d, t) {
			metaSent[d.toks[s.start].sent] = true
			anyMeta = true
		}
	}
	qs := map[int]bool{}
	for _, s := range e.find(d, e.meta.question) {
		qs[d.toks[s.start].sent] = true
	}
	for _, s := range e.find(d, e.meta.topic) {
		if qs[d.toks[s.start].sent] {
			metaSent[d.toks[s.start].sent] = true
			anyMeta = true
		}
	}
	mention := len(e.find(d, e.meta.mention)) > 0

	var hits []hit
	for i := range e.rules {
		r := &e.rules[i]
		if r.needFlag != "" && !d.flags[r.needFlag] {
			continue
		}
		sp, ok := e.matchSeq(d, r)
		if !ok {
			continue
		}
		w := r.w
		if (r.cat == PromptExtraction || r.cat == DataExfiltration) && sp.start > 0 && negators[d.toks[sp.start-1].key] {
			// "never reveal secrets", "không tiết lộ mật khẩu"
			w *= 0.3
		}
		if !r.noSuppress {
			f := 1.0
			if metaSent[d.toks[sp.start].sent] {
				f = min(f, metaFactor)
			}
			if d.quotedSpan(sp) && (anyMeta || mention || d.isCode) {
				f = min(f, quoteFactor)
			}
			if d.isCode && d.quotedSpan(sp) {
				// A string literal in code (test fixtures, detector patterns).
				// Comments are not suppressed: they are a carrier for
				// indirect injection into coding assistants.
				f = min(f, codeQuoteFactor)
			}
			w *= f
		}
		hits = append(hits, hit{id: r.id, cat: r.cat, w: w})
	}
	return hits
}

func (d *doc) quotedSpan(s span) bool {
	for i := s.start; i < s.end; i++ {
		if !d.toks[i].quoted {
			return false
		}
	}
	return true
}

// matchSeq reports whether the rule's terms occur in order within the gaps.
// It returns the span of the first chain found.
func (e *Engine) matchSeq(d *doc, r *rule) (span, bool) {
	if sp, ok := e.chain(d, r.seq, r); ok {
		return sp, true
	}
	if r.anyOrder && len(r.seq) == 2 {
		return e.chain(d, []*term{r.seq[1], r.seq[0]}, r)
	}
	return span{}, false
}

func (e *Engine) chain(d *doc, seq []*term, r *rule) (span, bool) {
	type state struct{ start, end int }
	var cur []state
	for i, t := range seq {
		spans := e.find(d, t)
		if len(spans) == 0 {
			return span{}, false
		}
		if i == 0 {
			for _, s := range spans {
				cur = append(cur, state{s.start, s.end})
			}
			continue
		}
		var next []state
		for _, s := range spans {
			for _, c := range cur {
				if s.start < c.end || s.start-c.end > r.gap {
					continue
				}
				if !r.crossSent && d.toks[s.start].sent != d.toks[c.start].sent {
					continue
				}
				next = append(next, state{c.start, s.end})
				break
			}
		}
		if len(next) == 0 {
			return span{}, false
		}
		cur = next
	}
	return span{cur[0].start, cur[0].end}, true
}

// find returns the spans where t matches, cached per doc.
func (e *Engine) find(d *doc, t *term) []span {
	if s, ok := d.cache[t.id]; ok {
		return s
	}
	var out []span
	for _, alt := range t.alts {
		first := alt[0]
		var starts []int
		if first.prefix {
			for i, tk := range d.toks {
				if strings.HasPrefix(tk.key, first.key) {
					starts = append(starts, i)
				}
			}
		} else {
			starts = d.index[first.key]
		}
	next:
		for _, st := range starts {
			if st+len(alt) > len(d.toks) {
				continue
			}
			for j := 1; j < len(alt); j++ {
				w, tk := alt[j], d.toks[st+j]
				if w.prefix && !strings.HasPrefix(tk.key, w.key) || !w.prefix && tk.key != w.key {
					continue next
				}
			}
			out = append(out, span{st, st + len(alt)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	d.cache[t.id] = out
	return out
}

// tokenize splits a skeleton into word tokens with sentence ids and a quoted
// flag. Glued words ("ignoreallpreviousinstructions") are split with the
// rule lexicon.
func (e *Engine) tokenize(s string) *doc {
	d := &doc{index: map[string][]int{}, cache: map[int][]span{}}
	sent, quoted := 0, false
	start := -1
	emit := func(end int) {
		w := s[start:end]
		start = -1
		for _, part := range e.split(w) {
			k := skeleton.Key(part)
			d.index[k] = append(d.index[k], len(d.toks))
			d.toks = append(d.toks, token{key: k, sent: sent, quoted: quoted})
		}
	}
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			emit(i)
		}
		switch r {
		case '"', '“', '”', '`', '«', '»', '「', '」', '‘', '’':
			quoted = !quoted
		case '\'':
			// An apostrophe between letters ("don't") is not a quote.
			prev, _ := utf8.DecodeLastRuneInString(s[:i])
			next, _ := utf8.DecodeRuneInString(s[i+1:])
			if !unicode.IsLetter(prev) || !unicode.IsLetter(next) {
				quoted = !quoted
			}
		case '\n', '!', '?', ';':
			sent++
		case '.':
			next, _ := utf8.DecodeRuneInString(s[i+1:])
			if i+1 >= len(s) || unicode.IsSpace(next) {
				sent++
			}
		}
	}
	if start >= 0 {
		emit(len(s))
	}
	return d
}

// split breaks a long word that is not in the lexicon into lexicon words when
// it can be covered completely, preferring fewer pieces.
func (e *Engine) split(w string) []string {
	if len(w) < 10 || len(w) > 80 || e.lexicon[skeleton.Key(w)] || !isASCIIWord(w) {
		return []string{w}
	}
	n := len(w)
	best := make([]int, n+1) // pieces needed to cover w[:i]; -1 unreachable
	prev := make([]int, n+1)
	for i := 1; i <= n; i++ {
		best[i] = -1
	}
	for i := 1; i <= n; i++ {
		for j := max(0, i-16); j < i; j++ {
			if best[j] < 0 {
				continue
			}
			piece := w[j:i]
			if len(piece) < 3 && !shortPieces[piece] {
				continue
			}
			if !e.lexicon[skeleton.Key(piece)] {
				continue
			}
			if best[i] < 0 || best[j]+1 < best[i] {
				best[i], prev[i] = best[j]+1, j
			}
		}
	}
	if best[n] < 2 {
		return []string{w}
	}
	var parts []string
	for i := n; i > 0; i = prev[i] {
		parts = append(parts, w[prev[i]:i])
	}
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return parts
}

// negators before a request verb turn it into a prohibition (skeleton keys).
var negators = map[string]bool{"never": true, "not": true, "dont": true, "cannot": true, "khong": true,
	"dung": true, "chang": true, "cam": true}

// shortPieces are the only words under three letters a glued word may be
// split into; single letters would let almost anything split.
var shortPieces = map[string]bool{"to": true, "me": true, "my": true, "of": true, "an": true, "is": true,
	"be": true, "do": true, "as": true, "or": true, "in": true, "on": true, "it": true}

func isASCIIWord(w string) bool {
	for i := 0; i < len(w); i++ {
		if w[i] < 'a' || w[i] > 'z' {
			return false
		}
	}
	return true
}

func (e *Engine) hasReversedCue(d *doc) bool {
	for _, t := range d.toks {
		if e.reversed[t.key] {
			return true
		}
	}
	return false
}

func reverse(s string) string {
	rs := []rune(s)
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	return string(rs)
}
