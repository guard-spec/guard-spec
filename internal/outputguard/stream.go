package outputguard

import (
	"strings"
	"unicode/utf8"
)

const (
	// Window is how much text a stream holds back. It is longer than any
	// personal-data pattern or canary, so none can straddle what was sent and
	// what is still held.
	Window = 256
	// maxLinkText is the longest link text the markdown detector accepts.
	maxLinkText = 1000
	// maxOpen bounds how long a stream waits for an image, link or URL to close.
	// Past it the construct is removed and the rest of it is dropped as it comes.
	maxOpen = 8192
)

// Stream guards text that arrives in pieces. Write returns the part that is
// safe to send; Flush returns the rest at the end.
type Stream struct {
	s       *Scanner
	buf     string // received, not yet sent
	ctx     string // the end of what was sent
	pending int    // bytes added since the last scan
	drop    dropUntil
	depth   int // parenthesis depth while dropping a markdown URL
	Counts  Counts
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
	st.buf += text
	st.pending += len(text)
	if len(st.buf) <= Window {
		return "" // all of it is inside the window: nothing can be sent yet
	}
	// Rescanning the buffer for every token would be wasteful; sending a few
	// bytes later is always safe, as the cut then has more context.
	if st.pending < scanEvery {
		return ""
	}
	st.pending = 0
	return st.emit(false)
}

// scanEvery is how many new bytes a stream collects before it scans again.
const scanEvery = 32

// Flush returns everything still held, with unfinished images and links removed.
func (st *Stream) Flush() string {
	var b strings.Builder
	for st.buf != "" {
		before := len(st.buf)
		b.WriteString(st.emit(true))
		if len(st.buf) == before {
			break // cannot place a cut safely: the rest is dropped
		}
	}
	st.buf, st.ctx, st.drop, st.depth = "", "", dropNone, 0
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

// emit renders and removes the safe prefix of buf, or all of it at the end.
func (st *Stream) emit(final bool) string {
	buf := st.buf
	// The text already sent before buf is scanned too, as context, so that line
	// starts, word boundaries and digit runs read as they do in the whole text.
	accepted, all := st.s.spans(st.ctx+buf, len(st.ctx))
	accepted, all = shift(accepted, len(st.ctx)), shift(all, len(st.ctx))
	open := st.openConstruct(buf, final)

	cut := len(buf) - Window
	if final {
		cut = len(buf)
	}
	if open.start >= 0 && open.start < cut {
		cut = open.start
	}
	// Never cut through a finding, accepted or not: it may change once the
	// rest of the text arrives.
	for moved := true; moved; {
		moved = false
		for _, c := range all {
			if c.start < cut && cut < c.end {
				cut, moved = c.start, true
			}
		}
	}
	for cut > 0 && cut < len(buf) && !utf8.RuneStart(buf[cut]) {
		cut--
	}
	if cut < 0 {
		cut = 0
	}

	var b strings.Builder
	last := 0
	for _, a := range accepted {
		if a.end > cut {
			break
		}
		b.WriteString(buf[last:a.start])
		b.WriteString(a.repl)
		st.Counts.add(a.counts)
		last = a.end
	}
	b.WriteString(buf[last:cut])
	st.buf = buf[cut:]
	st.ctx = tail(st.ctx+buf[:cut], contextLen)

	if open.force && open.start == cut {
		// The construct ran too long or the text ended inside it: remove it
		// and drop the rest of it as it arrives.
		b.WriteString(marker(open.kind))
		st.Counts[open.kind]++
		if n := strings.Count(st.buf, st.s.canary); st.s.canary != "" && n > 0 {
			st.Counts[KindCanary] += n
		}
		st.buf, st.ctx = "", ""
		st.drop = open.until
		st.depth = 0
	}
	return b.String()
}

// contextLen is how much sent text is kept as context for the next scan.
const contextLen = 16

// shift moves spans found in ctx+buf to buf's coordinates and drops those that
// start in ctx: that text was already sent.
func shift(spans []span, off int) []span {
	out := spans[:0:0]
	for _, s := range spans {
		if s.start >= off {
			s.start -= off
			s.end -= off
			out = append(out, s)
		}
	}
	return out
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
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
func (st *Stream) openConstruct(buf string, final bool) openSpan {
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
	consider(st.openRefDef(buf))
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
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t') {
		i++
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
		case c == ' ' || c == '\t' || c == '\n':
			// The URL ended. Only a title or the closing parenthesis may follow.
			for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n') {
				i++
			}
			if i == len(buf) {
				return start, true
			}
			switch buf[i] {
			case '"', '\'', '(':
				return start, !strings.ContainsRune(buf[i+1:], ')')
			case ')':
				return start, false
			default:
				return start, false // not a link after all
			}
		}
	}
	return start, true
}

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
	lower := strings.ToLower(buf)
	i := strings.LastIndex(lower, "<img")
	if i < 0 || strings.IndexByte(buf[i:], '>') >= 0 {
		// A short "<im" at the very end is covered by the window.
		return openSpan{start: -1}
	}
	return openSpan{start: i, force: final || len(buf)-i > maxOpen, kind: KindImage, until: dropTag}
}

// openRefDef finds a "[label]: url" line that has not ended yet.
func (st *Stream) openRefDef(buf string) openSpan {
	lineStart := strings.LastIndexByte(buf, '\n') + 1
	if lineStart == 0 && st.ctx != "" && !strings.HasSuffix(st.ctx, "\n") {
		return openSpan{start: -1} // buf starts mid-line
	}
	line := strings.TrimLeft(buf[lineStart:], " \t")
	if !strings.HasPrefix(line, "[") {
		return openSpan{start: -1}
	}
	k := strings.Index(line, "]:")
	if k < 0 {
		return openSpan{start: -1}
	}
	force := len(buf)-lineStart > maxOpen
	return openSpan{start: lineStart, force: force, kind: KindLink, until: dropLine}
}

// openBareURL finds a URL that runs to the end of buf: it may still turn out
// to be an image URL with a query.
func (st *Stream) openBareURL(buf string) openSpan {
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
