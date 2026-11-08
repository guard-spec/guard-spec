package outputguard

import (
	"strings"
	"unicode/utf8"
)

const (
	// Window bounds how long a word a stream holds back while it may still
	// grow into something to redact: an e-mail address, the canary, the start
	// of a URL. It is longer than any of them. Most of the time a stream holds
	// much less: only the end of the text that could still change (holdFrom).
	Window = 256
	// maxLinkText is the longest link text the markdown detector accepts.
	maxLinkText = 1000
	// maxOpen bounds how long a stream waits for an image, link or URL to close,
	// or for a run of digits to end. Past it the construct is removed and the
	// rest of it is dropped as it comes.
	maxOpen = 8192
)

// Stream guards text that arrives in pieces. Write returns the part that is
// safe to send; Flush returns the rest at the end.
type Stream struct {
	s *Scanner
	// text is the end of what was sent (text[:sent], kept as context so that
	// line starts, word boundaries and digit runs read as they do in the whole
	// text), then what was received and not sent yet (text[sent:]). Its
	// storage is reused from one delta to the next.
	text    []byte
	sent    int
	pending int // bytes added since the last scan
	drop    dropper
	// edits are the changes in the piece emit just produced.
	edits []edit
	// stages re-check what the first pass (emit) produced, then what each
	// re-check produced (settle).
	stages []stage
	Counts Counts
	// rest holds back the start of a token split across writes (WithTokens).
	rest restorer
}

// dropper discards the rest of a construct that was removed before it ended.
type dropper struct {
	until dropUntil
	depth int      // parenthesis depth while dropping a markdown URL
	tag   tagState // where the tokenizer is while dropping a start tag
}

type dropUntil int

const (
	dropNone dropUntil = iota
	dropParen
	dropTag
	dropLine
	dropSpace
)

// NewStream returns a Stream for one choice and field of a response.
func (s *Scanner) NewStream() *Stream {
	return &Stream{s: s, Counts: Counts{}}
}

// Write adds text and returns what can be sent now.
func (st *Stream) Write(text string) string {
	if st.s.tokens != nil {
		text = st.rest.write(text, st.s.tokens)
	}
	if st.s.g.passthrough {
		return text
	}
	return st.write(text)
}

func (st *Stream) write(text string) string {
	text = st.drop.skip(text)
	if text == "" {
		return ""
	}
	st.text = append(st.text, text...)
	st.pending += len(text)
	// Scanning for every token would be wasteful: tiny deltas are collected
	// first. Sending a few bytes later is always safe.
	if st.pending < scanEvery {
		return ""
	}
	st.pending = 0
	return st.settle(st.emit(false), false)
}

// scanEvery is how many new bytes a stream collects before it scans again.
const scanEvery = 64

// Flush returns everything still held, with unfinished images and links removed.
func (st *Stream) Flush() string {
	var b strings.Builder
	if st.s.tokens != nil {
		// The tail held back for a token that never closed.
		tail := st.rest.flush()
		if st.s.g.passthrough {
			return tail
		}
		b.WriteString(st.write(tail))
	} else if st.s.g.passthrough {
		return ""
	}
	for st.sent < len(st.text) {
		before := len(st.text) - st.sent
		b.WriteString(st.settle(st.emit(true), false))
		if len(st.text)-st.sent == before {
			break // cannot place a cut safely: the rest is dropped
		}
	}
	b.WriteString(st.settle("", true))
	st.text, st.sent, st.pending, st.drop = st.text[:0], 0, 0, dropper{}
	st.edits, st.stages = st.edits[:0], nil
	return b.String()
}

// skip discards the remainder of a construct removed earlier.
func (d *dropper) skip(text string) string {
	for d.until != dropNone && text != "" {
		i := 0
		for ; i < len(text); i++ {
			c := text[i]
			done := false
			switch d.until {
			case dropParen:
				switch {
				case c == '(':
					d.depth++
				case c == ')' && d.depth > 0:
					d.depth--
				case c == ')':
					done, i = true, i+1
				case c == ' ' || c == '\n' || c == '\t' || c == '\r':
					done = true
				}
			case dropTag:
				if d.tag = d.tag.next(c); d.tag == tagDone {
					done, i = true, i+1
				}
			case dropLine:
				done = c == '\n'
			case dropSpace:
				done = isURLStop(c)
			}
			if done {
				*d = dropper{}
				break
			}
		}
		text = text[i:]
	}
	return text
}

// emit renders and removes the safe prefix of what is held, or all of it at
// the end. The changes it made are left in st.edits.
func (st *Stream) emit(final bool) string {
	st.edits = st.edits[:0]
	text := string(st.text)
	ctx, buf := text[:st.sent], text[st.sent:]
	// The text already sent is scanned too, as context; findings that start in
	// it were dealt with before.
	accepted, all := st.s.spans(text, st.sent)
	shift(accepted, st.sent)
	shift(all, st.sent)
	open := st.openConstruct(ctx, buf, final)

	cut := len(buf)
	if !final {
		cut = st.holdFrom(ctx, buf)
	}
	if open.start >= 0 && open.start < cut {
		cut = open.start
	}
	// Never cut through a finding, accepted or not: it may change once the
	// rest of the text arrives. Nor through a run of digits: card numbers are
	// found by grouping the whole run, and phone numbers by its edges.
	for moved := true; moved; {
		moved = false
		for _, c := range all {
			if c.start < cut && cut < c.end {
				cut, moved = c.start, true
			}
		}
		if cut >= len(buf) {
			continue // the end: holdFrom decided on an open run
		}
		if r := numericRunStart(buf, cut); r < cut && len(buf)-r <= maxOpen {
			cut, moved = r, true
		}
	}
	for cut > 0 && cut < len(buf) && !utf8.RuneStart(buf[cut]) {
		cut--
	}

	var b strings.Builder
	last := 0
	for _, a := range accepted {
		if a.end > cut {
			break
		}
		b.WriteString(buf[last:a.start])
		st.edits = append(st.edits, st.apply(&b, a))
		last = a.end
	}
	b.WriteString(buf[last:cut])
	// Keep the last contextLen bytes of what was sent, whole characters only.
	end := st.sent + cut
	keep := max(0, end-contextLen)
	for keep < end && !utf8.RuneStart(text[keep]) {
		keep++
	}
	st.text, st.sent = st.text[:copy(st.text, text[keep:])], end-keep

	if open.force && open.start == cut {
		// The construct ran too long or the text ended inside it: remove it
		// and drop the rest of it as it arrives.
		st.edits = append(st.edits, st.force(&b, open, buf[cut:]))
		st.text, st.sent = st.text[:0], 0
		st.drop = dropper{until: open.until, tag: open.tag}
	}
	return b.String()
}

// apply writes the replacement of a to b, counts a, and returns the edit.
func (st *Stream) apply(b *strings.Builder, a span) edit {
	e := edit{start: b.Len(), link: a.kind == KindLink}
	b.WriteString(a.repl)
	e.end = b.Len()
	st.Counts.addSpan(a)
	return e
}

// force writes the marker of an open construct removed before it ended, rest
// being the part of it received so far, and returns the edit.
func (st *Stream) force(b *strings.Builder, open openSpan, rest string) edit {
	e := edit{start: b.Len()}
	b.WriteString(marker(open.kind))
	e.end = b.Len()
	st.Counts[open.kind]++
	if n := strings.Count(rest, st.s.canary); st.s.canary != "" && n > 0 {
		st.Counts[KindCanary] += n
	}
	return e
}

// contextLen is how much sent text is kept as context for the next scan.
const contextLen = 16

// maxRechecks bounds how many times the guard re-checks what it produced.
// A re-check only finds something once the one before it changed something,
// which takes markup nested for that purpose: the last one does not rewrite
// what it finds, it ends the text there.
const maxRechecks = 3

// stage is one re-check of what the pass before it produced. A removal joins
// what was around it, and a marker sits where the removed markup was: either
// can form an image, a link, a reference definition or a URL that was not in
// the answer as such (`![x][]()(https://evil.com/a.png)`, "[REDACTED:image]"
// followed by "(https://...)"), and a removed link can join the parts of the
// canary or of personal data. While what it holds has changes of the pass
// before it, a stage looks at it again with the same detectors (spansIn),
// and it holds back the end of what it got while a change may still come next
// to it. Each stage applies the same rules to what the one before it produces
// as the first pass applies to the answer, so a stream sends what the whole
// answer would be.
type stage struct {
	level int // 1 for the re-check of the first pass
	// out is the end of what the stage sent (out[:outSent], context), then
	// what it got and holds. edits are the changes the pass before it made in
	// out, sorted; those that nothing still held can touch are dropped.
	out      []byte
	outSent  int
	edits    []edit
	joins    []int // scratch: the joins of edits
	drop     dropper
	dead     bool   // the last re-check found something: the rest is dropped
	newEdits []edit // the changes in the piece settle just produced
}

// settle passes piece, the output of the first pass with its changes in
// st.edits, through the re-checks.
func (st *Stream) settle(piece string, final bool) string {
	if st.stages == nil {
		// All of them, from the start: a stage that changes nothing yet must
		// still hold back what a change before it may join, and what it
		// changes later may join what it sent before.
		st.stages = make([]stage, maxRechecks)
		for i := range st.stages {
			st.stages[i].level = i + 1
		}
	}
	edits := st.edits
	for i := range st.stages {
		piece, edits = st.recheck(&st.stages[i], piece, edits, final, st.upstream(i))
	}
	st.edits = st.edits[:0]
	return piece
}

// upstream returns the text that comes after what stage i got: what the
// nearest pass before it still holds.
func (st *Stream) upstream(i int) []byte {
	for j := i - 1; j >= 0; j-- {
		if sg := &st.stages[j]; sg.outSent < len(sg.out) && !sg.dead {
			return sg.out[sg.outSent:]
		}
	}
	return st.text[st.sent:]
}

// recheck is one stage's work on piece, with edits the changes in it. up is
// what the passes before it still hold. It returns what the stage sends and
// the changes it made in that.
func (st *Stream) recheck(sg *stage, piece string, edits []edit, final bool, up []byte) (string, []edit) {
	sg.newEdits = sg.newEdits[:0]
	if sg.dead {
		return "", nil
	}
	if sg.drop.until != dropNone {
		rest := sg.drop.skip(piece)
		k := len(piece) - len(rest)
		piece, edits = rest, dropEdits(edits, k)
	}
	base := len(sg.out)
	if len(edits) == 0 && len(sg.edits) == 0 && base == sg.outSent && !final {
		// Nothing changed and nothing held, as is most often the case: only
		// the end of piece may have to wait, and only that and the context
		// before it are kept.
		cut := len(piece)
		if len(up) > 0 {
			ctx := string(sg.out)
			cut = structHold(ctx, piece)
			if st.s.canary != "" || st.s.g.cfg.RedactPII {
				cut = min(cut, st.joinHold(sg, piece, up))
			}
			if open := st.openConstruct(ctx, piece, false); open.start >= 0 && open.start < cut {
				cut = open.start
			}
			for cut > 0 && cut < len(piece) && !utf8.RuneStart(piece[cut]) {
				cut--
			}
		}
		keep := max(0, cut-contextLen)
		for keep < cut && !utf8.RuneStart(piece[keep]) {
			keep++
		}
		if cut < contextLen {
			sg.out = append(sg.out, piece...)
			sg.keepOut(base + cut)
		} else {
			sg.out, sg.outSent = append(sg.out[:0], piece[keep:]...), cut-keep
		}
		return piece[:cut], nil
	}
	sg.out = append(sg.out, piece...)
	for _, e := range edits {
		sg.edits = append(sg.edits, edit{start: base + e.start, end: base + e.end, link: e.link})
	}
	pending := len(sg.edits) > 0
	if !pending && (final || len(up) == 0) {
		// Nothing changed, and nothing held before it can still change next
		// to it: the piece goes on as it is.
		buf := piece
		if base > sg.outSent {
			buf = string(sg.out[sg.outSent:])
		}
		sg.keepOut(len(sg.out))
		return buf, nil
	}
	var ctx, buf, text string
	if pending || base > sg.outSent {
		text = string(sg.out)
		ctx, buf = text[:sg.outSent], text[sg.outSent:]
	} else {
		ctx, buf = string(sg.out[:sg.outSent]), piece
	}
	inline := st.s.canary != "" || st.s.g.cfg.RedactPII

	open := openSpan{start: -1}
	if !final || pending {
		open = st.openConstruct(ctx, buf, final)
		if !pending {
			// Only a change can form a construct the first pass did not
			// remove; others are held, never removed here.
			open.force = false
		}
	}
	cut := len(buf)
	if !final {
		cut = structHold(ctx, buf)
		if inline {
			cut = min(cut, st.joinHold(sg, buf, up))
		}
	}
	if open.start >= 0 && open.start < cut {
		cut = open.start
	}
	var accepted, all []span
	if pending {
		if sg.joins == nil {
			sg.joins = make([]int, 0, 8) // not nil: a re-check
		}
		joins := sg.joins[:0]
		if inline {
			for _, e := range sg.edits {
				if e.link {
					joins = append(joins, e.start)
					if e.end > e.start {
						joins = append(joins, e.end)
					}
				}
			}
		}
		sg.joins = joins
		accepted, all = st.s.spansIn(text, sg.outSent, joins)
		shift(accepted, sg.outSent)
		shift(all, sg.outSent)
		// Never cut through a finding, nor, near a join, through a run of
		// digits.
		for moved := true; moved; {
			moved = false
			for _, c := range all {
				if c.start < cut && cut < c.end {
					cut, moved = c.start, true
				}
			}
			if len(joins) > 0 && cut < len(buf) {
				if s := numericRunStart(buf, cut); s < cut && len(buf)-s <= maxOpen {
					cut, moved = s, true
				}
			}
		}
	}
	for cut > 0 && cut < len(buf) && !utf8.RuneStart(buf[cut]) {
		cut--
	}

	forced := open.force && open.start == cut
	if sg.level == maxRechecks {
		// The last re-check: what it finds is not rewritten, since that could
		// form something again. The text ends there, with a marker.
		if len(accepted) > 0 && accepted[0].end <= cut {
			end := accepted[0].start
			for _, c := range all {
				end = min(end, c.start)
			}
			var b strings.Builder
			b.WriteString(buf[:end])
			st.force(&b, openSpan{kind: accepted[0].kind}, buf[end:])
			sg.dead = true
			return b.String(), nil
		}
		if forced {
			var b strings.Builder
			b.WriteString(buf[:cut])
			st.force(&b, open, buf[cut:])
			sg.dead = true
			return b.String(), nil
		}
	}
	if len(accepted) == 0 && !forced {
		sg.keepOut(sg.outSent + cut)
		return buf[:cut], nil
	}
	var b strings.Builder
	last := 0
	for _, a := range accepted {
		if a.end > cut {
			break
		}
		b.WriteString(buf[last:a.start])
		sg.newEdits = append(sg.newEdits, st.apply(&b, a))
		last = a.end
	}
	b.WriteString(buf[last:cut])
	sg.keepOut(sg.outSent + cut)
	if forced {
		sg.newEdits = append(sg.newEdits, st.force(&b, open, buf[cut:]))
		sg.out, sg.outSent, sg.edits = sg.out[:0], 0, sg.edits[:0]
		sg.drop = dropper{until: open.until, tag: open.tag}
	}
	return b.String(), sg.newEdits
}

// dropEdits returns edits, made in a piece whose first k bytes were dropped,
// in the coordinates of the rest. An edit that ends in the dropped part is
// kept as an empty one at the start when it ends where the rest starts.
func dropEdits(edits []edit, k int) []edit {
	if k == 0 {
		return edits
	}
	var out []edit
	for _, e := range edits {
		if e.end >= k {
			out = append(out, edit{start: max(0, e.start-k), end: e.end - k, link: e.link})
		}
	}
	return out
}

// keepOut drops what the stage sent, up to end in out, but for the last
// contextLen bytes, whole characters only, and the edits that nothing still
// held can touch.
func (sg *stage) keepOut(end int) {
	keep := max(0, end-contextLen)
	for keep < end && !utf8.RuneStart(sg.out[keep]) {
		keep++
	}
	sg.out, sg.outSent = sg.out[:copy(sg.out, sg.out[keep:])], end-keep
	k := 0
	for _, e := range sg.edits {
		// What is held from end on can touch an edit only if it ends there
		// or later.
		if e.end >= end {
			sg.edits[k] = edit{start: e.start - keep, end: e.end - keep, link: e.link}
			k++
		}
	}
	sg.edits = sg.edits[:k]
}

// shift moves spans found in ctx+buf to buf's coordinates, in place. Spans
// that start in ctx were left out by spans already.
func shift(spans []span, off int) {
	for i := range spans {
		spans[i].start -= off
		spans[i].end -= off
	}
}

// holdFrom returns where the end of buf that must be held back starts: the
// part that, depending on what comes next, could still become (or extend) a
// finding that starts there. Constructs that have opened (images, links, tags,
// URLs, reference definitions) are held by openConstruct, and findings that
// already match by emit; this covers what does not match anything yet.
func (st *Stream) holdFrom(ctx, buf string) int {
	return min(st.tokenHold(buf, Window), structHold(ctx, buf))
}

// structHold is the part of holdFrom that does not depend on what the guard
// redacts within words: the end of buf that may still become an image, a
// link, a tag, a URL or a reference definition.
func structHold(ctx, buf string) int {
	n := len(buf)
	if n == 0 {
		return 0
	}
	hold := n
	// The beginning of a URL, in any case.
	for _, p := range [...]string{"https://", "http://", "www."} {
		for k := min(len(p), n); k > 0; k-- {
			if hasPrefixFold(buf[n-k:], p[:k]) {
				hold = min(hold, n-k)
				break
			}
		}
	}
	// "!" may start an image, "]" the "](" of a link, and "<" a tag.
	if c := buf[n-1]; c == '!' || c == ']' || c == '<' {
		hold = min(hold, n-1)
	}
	// A line that may still become a reference definition: blanks and
	// blockquote markers, then possibly "[label" or "[label]".
	if ls := strings.LastIndexByte(buf, '\n') + 1; ls > 0 || ctx == "" || strings.HasSuffix(ctx, "\n") {
		line := strings.TrimLeft(buf[ls:], " \t>")
		if (line == "" && ls < n) || (line != "" && line[0] == '[' && refLabelOpen(line)) {
			hold = min(hold, max(ls, n-Window))
		}
	}
	return hold
}

// joinHold returns where the end of buf, the end of what a stage got, must be
// held back because a removed link may join it to what follows. That is so
// when the value it may start holds a join already, or may still grow up to
// one (a removal ends buf), and while the passes before hold text (up) that
// goes on with the same word or number, or that starts with what a removed
// link starts with ("[" or "]", "<" for a tag, or blanks at a line start).
// The word is bounded by Window together with how it goes on in the held
// text, as in the first pass.
func (st *Stream) joinHold(sg *stage, buf string, up []byte) int {
	hold := len(buf)
	for i := len(sg.edits) - 1; i >= 0; i-- {
		if e := sg.edits[i]; e.link {
			if h := st.tokenHold(buf, Window); e.end >= sg.outSent+h {
				hold = h
			}
			break
		}
	}
	if len(up) == 0 {
		return hold
	}
	if c := up[0]; !wordByte(c) && c != '[' && c != ']' && c != '<' && c != ' ' && c != '\t' {
		return hold
	}
	run := 0
	for run < len(up) && wordByte(up[run]) {
		run++
	}
	return min(hold, st.tokenHold(buf, Window-run))
}

// tokenHold returns where the end of buf that may still be the first part of
// the canary or of personal data starts (len(buf) when there is none). A word
// is held up to window bytes.
func (st *Stream) tokenHold(buf string, window int) int {
	n := len(buf)
	hold := n
	// A word that may still become an e-mail address, the canary, a number,
	// or the "http"/"www" of a URL.
	i := n
	for i > 0 && wordByte(buf[i-1]) {
		i--
	}
	if i < n && window > 0 {
		hold = max(i, n-window)
	}
	// A run of digits that may still grow into a card or phone number.
	if r := numericRunStart(buf, n); r < n && n-r <= maxOpen {
		hold = min(hold, r)
	}
	// The beginning of the canary, whatever its characters.
	if c := st.s.canary; c != "" {
		for j := max(0, n-len(c)+1); j < n; j++ {
			if buf[j] == c[0] && strings.HasPrefix(c, buf[j:]) {
				hold = min(hold, j)
				break
			}
		}
	}
	return hold
}

// wordByte reports whether c can be part of an e-mail address or the canary.
func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '%' || c == '+' || c == '-' || c == '@'
}

// refLabelOpen reports whether line, which starts with "[", may still be the
// "[label]:" of a reference definition.
func refLabelOpen(line string) bool {
	k := strings.IndexByte(line, ']')
	return k < 0 || k == len(line)-1 || line[k+1] == ':'
}

func numSep(c byte) bool { return c == ' ' || c == '.' || c == '-' }

// numericRunStart returns the start of the run of digits that position i of s
// lies inside, or i when it is not inside one. A run is what card, phone,
// citizen ID and IPv4 numbers are made of: an optional "+", then digits with
// single spaces, dots or dashes between them. At the end of s (i == len(s)) a
// run is open when s ends in a digit, in a digit and a separator, or in "+".
func numericRunStart(s string, i int) int {
	n := len(s)
	if i <= 0 || i > n {
		return i
	}
	j := i // s[j-1] is a digit of the run
	switch {
	case i == n:
		switch {
		case s[n-1] == '+':
			return n - 1
		case numSep(s[n-1]) && n >= 2 && isDigit(s[n-2]):
			j = n - 1
		case !isDigit(s[n-1]):
			return i
		}
	case isDigit(s[i-1]) && (isDigit(s[i]) || numSep(s[i]) && (i+1 == n || isDigit(s[i+1]))):
	case numSep(s[i-1]) && isDigit(s[i]) && i >= 2 && isDigit(s[i-2]):
		j = i - 1
	case s[i-1] == '+' && isDigit(s[i]):
		return i - 1
	default:
		return i
	}
	k := j - 1
	for {
		for k > 0 && isDigit(s[k-1]) {
			k--
		}
		if k >= 2 && numSep(s[k-1]) && isDigit(s[k-2]) {
			k -= 2
			continue
		}
		break
	}
	if k > 0 && s[k-1] == '+' {
		k--
	}
	return k
}

// openSpan is an image, link or URL that has started but not finished.
type openSpan struct {
	start int // -1 when nothing is open
	force bool
	kind  string
	until dropUntil
	tag   tagState // for a start tag, the tokenizer's state at the end
}

// openConstruct finds the earliest construct in buf that is still open and that
// could turn into something the guard removes once it is complete.
func (st *Stream) openConstruct(ctx, buf string, final bool) openSpan {
	best := openSpan{start: -1}
	consider := func(o openSpan) {
		if final && !o.force {
			return // at the end only what must be removed matters
		}
		if o.start >= 0 && (best.start < 0 || o.start < best.start) {
			best = o
		}
	}
	consider(st.openMarkdownURL(buf, final))
	consider(openLinkText(buf))
	consider(st.openTag(buf))
	consider(openRefDef(ctx, buf))
	consider(st.openBareURL(buf))
	return best
}

// openMarkdownURL finds "](" whose URL has not been closed by ")".
func (st *Stream) openMarkdownURL(buf string, final bool) openSpan {
	for off := 0; ; {
		i := strings.Index(buf[off:], "](")
		if i < 0 {
			return openSpan{start: -1}
		}
		i += off
		off = i + 2
		urlStart, urlOpen := mdURLOpen(buf, i+2)
		if !urlOpen {
			continue
		}
		start, kind := i, KindLink
		if j := strings.LastIndexAny(buf[:i], "[]\n"); j >= 0 && buf[j] == '[' && i-j <= maxLinkText+1 {
			start = j
			if j > 0 && buf[j-1] == '!' {
				start, kind = j-1, KindImage
			}
		}
		long := len(buf)-start > maxOpen
		if st.s.g.allowed(strings.TrimLeft(buf[urlStart:], " \t<")) {
			// To an allowed host so far: hold it until it closes, since the host
			// may still change ("allowed.com.evil.com"). At the end, or once
			// it is long enough that the host is settled, let it go.
			if final || long {
				return openSpan{start: -1}
			}
			return openSpan{start: start, kind: kind}
		}
		return openSpan{start: start, force: final || long, kind: kind, until: dropParen}
	}
}

// mdURLOpen reports whether the markdown URL starting at i, after "](", runs
// to the end of buf before the link is complete (mdLinkTail). It also
// returns where the URL starts.
func mdURLOpen(buf string, i int) (int, bool) {
	_, _, _, _, open := mdLinkTail(buf, i)
	return i, open
}

// isSpace is \s of the regular expressions.
func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// openLinkText finds "[" (or "![") with no "]" yet, or whose "]" ends buf, so
// that "(" may still follow. Long link text is let go: the tail of the link is
// still caught by its own pattern.
func openLinkText(buf string) openSpan {
	j := strings.LastIndexAny(buf, "[\n")
	if j < 0 || buf[j] != '[' {
		return openSpan{start: -1}
	}
	rest := buf[j+1:]
	k := strings.IndexByte(rest, ']')
	if k >= 0 && k != len(rest)-1 {
		return openSpan{start: -1}
	}
	if len(buf)-j > maxLinkText+2 {
		return openSpan{start: -1}
	}
	if j > 0 && buf[j-1] == '!' {
		j--
	}
	return openSpan{start: j}
}

// openTag finds the first start tag that has not closed (scanTags): it may
// still get an attribute the guard removes it for. One open longer than
// maxOpen is removed, and the rest of it dropped as it comes.
func (st *Stream) openTag(buf string) openSpan {
	if strings.IndexByte(buf, '<') < 0 {
		return openSpan{start: -1}
	}
	_, t := st.s.g.scanTags(buf)
	if t.start < 0 {
		// A "<" at the very end is held by holdFrom.
		return openSpan{start: -1}
	}
	return openSpan{start: t.start, force: len(buf)-t.start > maxOpen, kind: KindImage, until: dropTag, tag: t.state}
}

// openRefDef finds a "[label]: url" line that has not ended yet.
func openRefDef(ctx, buf string) openSpan {
	lineStart := strings.LastIndexByte(buf, '\n') + 1
	atLineStart := func(i int) bool {
		return i > 0 || ctx == "" || strings.HasSuffix(ctx, "\n")
	}
	start := -1
	if atLineStart(lineStart) && isRefLabel(buf[lineStart:]) {
		start = lineStart
	} else if lineStart > 0 {
		// The label may end the previous line, with the URL on this one.
		prevStart := strings.LastIndexByte(buf[:lineStart-1], '\n') + 1
		prev := buf[prevStart : lineStart-1]
		if atLineStart(prevStart) && isRefLabel(prev) &&
			strings.TrimRight(prev[strings.Index(prev, "]:")+2:], " \t") == "" {
			start = prevStart
		}
	}
	if start < 0 {
		return openSpan{start: -1}
	}
	force := len(buf)-start > maxOpen
	return openSpan{start: start, force: force, kind: KindLink, until: dropLine}
}

// isRefLabel reports whether line starts like a reference definition,
// "[label]:", possibly inside a blockquote.
func isRefLabel(line string) bool {
	line = strings.TrimLeft(line, " \t>")
	return strings.HasPrefix(line, "[") && strings.Contains(line, "]:")
}

// openBareURL finds a URL that runs to the end of buf: it may still turn out
// to be an image URL with a query. Every URL that starts in the stretch of
// text at the end of buf runs to its end.
func (st *Stream) openBareURL(buf string) openSpan {
	if !hasURLStart(buf) {
		return openSpan{start: -1}
	}
	k := len(buf)
	for k > 0 && !isURLStop(buf[k-1]) {
		k--
	}
	for _, u := range bareURLs(buf[k:]) {
		o := openSpan{start: k + u.start, kind: KindURL, until: dropSpace}
		if len(buf)-o.start > maxOpen {
			raw := buf[o.start:]
			if !u.query || !u.many && (st.s.g.allowed(raw) || parseURL(raw) == nil || parseURL(raw).RawQuery == "") {
				// Without a query it cannot carry data the way the guard
				// removes; another URL in it may still.
				continue
			}
			o.force = true
		}
		return o
	}
	return openSpan{start: -1}
}
