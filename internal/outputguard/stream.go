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
	drop    dropUntil
	depth   int // parenthesis depth while dropping a markdown URL
	// The second pass (settle) works on what the first pass produced: out is
	// the end of what was sent (out[:outSent], context), then what the first
	// pass produced and the second holds. joins are the positions in out where
	// the first pass removed something, or kept only the text of a link, so
	// that text which was apart in the answer now touches. newJoins are those
	// of the piece emit just produced.
	out      []byte
	outSent  int
	joins    []int
	newJoins []int
	Counts   Counts
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
	text = st.skipDropped(text)
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
	for st.sent < len(st.text) {
		before := len(st.text) - st.sent
		b.WriteString(st.settle(st.emit(true), false))
		if len(st.text)-st.sent == before {
			break // cannot place a cut safely: the rest is dropped
		}
	}
	b.WriteString(st.settle("", true))
	st.text, st.sent, st.pending, st.drop, st.depth = st.text[:0], 0, 0, dropNone, 0
	st.out, st.outSent, st.joins = st.out[:0], 0, st.joins[:0]
	return b.String()
}

// skipDropped discards the remainder of a construct removed earlier.
func (st *Stream) skipDropped(text string) string {
	for st.drop != dropNone && text != "" {
		i := 0
		for ; i < len(text); i++ {
			c := text[i]
			done := false
			switch st.drop {
			case dropParen:
				switch {
				case c == '(':
					st.depth++
				case c == ')' && st.depth > 0:
					st.depth--
				case c == ')':
					done, i = true, i+1
				case c == ' ' || c == '\n' || c == '\t' || c == '\r':
					done = true
				}
			case dropTag:
				if c == '>' {
					done, i = true, i+1
				}
			case dropLine:
				done = c == '\n'
			case dropSpace:
				done = c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '<' || c == '>' || c == '"'
			}
			if done {
				st.drop, st.depth = dropNone, 0
				break
			}
		}
		text = text[i:]
	}
	return text
}

// emit renders and removes the safe prefix of what is held, or all of it at
// the end.
func (st *Stream) emit(final bool) string {
	st.newJoins = st.newJoins[:0]
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
		// A removed link (only its text is kept, if any) joins what was
		// around it. Markers cannot join anything: their brackets and colon
		// are part of no value the guard looks for.
		join := a.kind == KindLink
		if join {
			st.newJoins = append(st.newJoins, b.Len())
		}
		b.WriteString(a.repl)
		if join && a.repl != "" {
			st.newJoins = append(st.newJoins, b.Len())
		}
		st.Counts.addSpan(a)
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
		b.WriteString(marker(open.kind))
		st.Counts[open.kind]++
		if n := strings.Count(buf[cut:], st.s.canary); st.s.canary != "" && n > 0 {
			st.Counts[KindCanary] += n
		}
		st.text, st.sent = st.text[:0], 0
		st.drop = open.until
		st.depth = 0
	}
	return b.String()
}

// contextLen is how much sent text is kept as context for the next scan.
const contextLen = 16

// settle is the second pass, over what the first pass (emit) produced: piece,
// with its joins in newJoins. A removal can join the parts of a value that the
// first pass saw apart, such as the canary split by "[]()", so the second pass
// looks again for the canary and personal data, but only for matches that
// hold a join: everything else the first pass has decided on already. Like
// the first pass, it holds back the end of what it got that could still be
// the first part of such a value, until what follows is known.
func (st *Stream) settle(piece string, final bool) string {
	if st.s.canary == "" && !st.s.g.cfg.RedactPII {
		return piece // nothing a join could form is looked for
	}
	if len(st.joins) == 0 && len(st.newJoins) == 0 && st.outSent == len(st.out) {
		// Nothing held and nothing joined, as is most often the case: only
		// the end of piece may still be the first part of a value.
		cut := len(piece)
		if !final {
			cut = st.joinHold(piece)
		}
		if cut < contextLen {
			st.out = append(st.out, piece...)
			st.keepOut(len(st.out) - len(piece) + cut)
			return piece[:cut]
		}
		keep := cut - contextLen
		for keep < cut && !utf8.RuneStart(piece[keep]) {
			keep++
		}
		st.out, st.outSent = append(st.out[:0], piece[keep:]...), cut-keep
		return piece[:cut]
	}
	base := len(st.out)
	st.out = append(st.out, piece...)
	for _, j := range st.newJoins {
		st.joins = append(st.joins, base+j)
	}
	st.newJoins = st.newJoins[:0]
	text := string(st.out)
	buf := text[st.outSent:]
	cut := len(buf)
	if !final {
		cut = st.joinHold(buf)
	}
	var found []span
	if len(st.joins) > 0 {
		found = st.s.inlineMatchesAcross(text, st.outSent, st.joins)
		shift(found, st.outSent)
		// Never cut through a joined value, nor through a run of digits.
		for moved := true; moved; {
			moved = false
			for _, f := range found {
				if f.start < cut && cut < f.end {
					cut, moved = f.start, true
				}
			}
			if cut < len(buf) {
				if r := numericRunStart(buf, cut); r < cut && len(buf)-r <= maxOpen {
					cut, moved = r, true
				}
			}
		}
	}
	for cut > 0 && cut < len(buf) && !utf8.RuneStart(buf[cut]) {
		cut--
	}
	st.keepOut(st.outSent + cut)
	if len(found) == 0 || found[0].end > cut {
		return buf[:cut]
	}
	var b strings.Builder
	last := 0
	for _, f := range found {
		if f.end > cut {
			break
		}
		b.WriteString(buf[last:f.start])
		b.WriteString(f.repl)
		st.Counts.addSpan(f)
		last = f.end
	}
	b.WriteString(buf[last:cut])
	return b.String()
}

// keepOut drops what the second pass sent, up to end in out, but for the last
// contextLen bytes, whole characters only, and the joins that nothing still
// held can hold.
func (st *Stream) keepOut(end int) {
	keep := max(0, end-contextLen)
	for keep < end && !utf8.RuneStart(st.out[keep]) {
		keep++
	}
	st.out, st.outSent = st.out[:copy(st.out, st.out[keep:])], end-keep
	k := 0
	for _, j := range st.joins {
		// A value held from end on cannot hold a join at or before end.
		if j > end {
			st.joins[k] = j - keep
			k++
		}
	}
	st.joins = st.joins[:k]
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
	n := len(buf)
	if n == 0 {
		return 0
	}
	hold := st.tokenHold(buf, Window)
	// The beginning of a URL or an <img> tag, in any case.
	for _, p := range [...]string{"https://", "http://", "www.", "<img"} {
		for k := min(len(p), n); k > 0; k-- {
			if hasPrefixFold(buf[n-k:], p[:k]) {
				hold = min(hold, n-k)
				break
			}
		}
	}
	// "!" may start an image, and "]" the "](" of a link.
	if c := buf[n-1]; c == '!' || c == ']' {
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

// joinHold returns where the end of buf, the end of what the first pass
// produced, must be held back by the second pass because a removal may join
// it to what follows. That is so when the value it may start holds a join
// already, or may still grow up to one (a removal ends buf), and while the
// first pass holds text that goes on with the same word or number, or that
// starts with what a removed link starts with ("[" or "]", or blanks at a
// line start). The word is bounded by Window together with how it goes on in
// the held text, as in the first pass.
func (st *Stream) joinHold(buf string) int {
	hold := len(buf)
	if n := len(st.joins); n > 0 {
		if h := st.tokenHold(buf, Window); st.joins[n-1] >= st.outSent+h {
			hold = h
		}
	}
	held := st.text[st.sent:]
	if len(held) == 0 {
		return hold
	}
	if c := held[0]; !wordByte(c) && c != '[' && c != ']' && c != ' ' && c != '\t' {
		return hold
	}
	run := 0
	for run < len(held) && wordByte(held[run]) {
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
	consider(st.openTag(buf, final))
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

// mdURLOpen reports whether the markdown URL starting at i runs to the end of
// buf without its closing parenthesis. It also returns where the URL starts.
func mdURLOpen(buf string, i int) (int, bool) {
	start := i
	for i < len(buf) && isSpace(buf[i]) {
		i++
	}
	if i < len(buf) && buf[i] == '<' {
		// <...> may hold spaces; it ends at ">" and cannot span lines.
		end := strings.IndexAny(buf[i:], ">\n")
		if end < 0 {
			return start, true
		}
		if buf[i+end] == '\n' {
			return start, false
		}
		i += end + 1
	}
	depth := 0
	for ; i < len(buf); i++ {
		c := buf[i]
		switch {
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == ')':
			return start, false
		case isSpace(c):
			// The URL ended. Only a title or the closing parenthesis may follow.
			for i < len(buf) && isSpace(buf[i]) {
				i++
			}
			if i == len(buf) {
				return start, true
			}
			switch buf[i] {
			case '"', '\'', '(':
				return start, mdTitleOpen(buf, i)
			default:
				return start, false // closed by ")", or not a link after all
			}
		}
	}
	return start, true
}

// mdTitleOpen reports whether the link title starting at buf[i] ("..." or
// '...' or (...), on one line) and the ")" that must follow it may still
// complete.
func mdTitleOpen(buf string, i int) bool {
	closer := buf[i]
	if closer == '(' {
		closer = ')'
	}
	j := i + 1
	for j < len(buf) && buf[j] != closer && buf[j] != '\n' && (buf[i] != '(' || buf[j] != '(') {
		j++
	}
	if j == len(buf) {
		return true // the title is still open
	}
	if buf[j] != closer {
		return false // not a title: not a link
	}
	j++
	for j < len(buf) && isSpace(buf[j]) {
		j++
	}
	return j == len(buf) // else ")" closed it, or it is not a link
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

// openTag finds "<img" without its closing ">".
func (st *Stream) openTag(buf string, final bool) openSpan {
	i := lastIndexFold(buf, "<img")
	if i < 0 || strings.IndexByte(buf[i:], '>') >= 0 {
		// A short "<im" at the very end is held by holdFrom.
		return openSpan{start: -1}
	}
	return openSpan{start: i, force: final || len(buf)-i > maxOpen, kind: KindImage, until: dropTag}
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
// to be an image URL with a query.
func (st *Stream) openBareURL(buf string) openSpan {
	if !hasURLStart(buf) {
		return openSpan{start: -1}
	}
	locs := bareURLRe.FindAllStringIndex(buf, -1)
	if len(locs) == 0 {
		return openSpan{start: -1}
	}
	m := locs[len(locs)-1]
	if m[1] != len(buf) {
		return openSpan{start: -1}
	}
	o := openSpan{start: m[0], kind: KindURL, until: dropSpace}
	if len(buf)-m[0] > maxOpen {
		raw := buf[m[0]:]
		if st.s.g.allowed(raw) || parseURL(raw) == nil || parseURL(raw).RawQuery == "" {
			// Without a query it cannot carry data the way the guard removes.
			return openSpan{start: -1}
		}
		o.force = true
	}
	return o
}
