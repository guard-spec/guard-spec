// Package outputguard rewrites model output before it reaches the client. It
// removes markdown images and links that could carry data to a third-party host,
// redacts personal data, and catches a leaked canary token. It works on whole
// responses and on event streams, where it holds back a short window of text so
// that a pattern split across chunks is still caught.
package outputguard

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Kinds of findings, as counted in Counts and written in redaction markers.
const (
	KindImage  = "image"  // markdown or HTML image to a host not on the allowlist
	KindLink   = "link"   // link to a host not on the allowlist; its text is kept
	KindURL    = "url"    // bare image URL carrying a query string
	KindCanary = "canary" // the request's canary token
	KindEmail  = "email"
	KindPhone  = "phone" // Vietnamese phone number, +84 or 0 forms
	KindCCCD   = "cccd"  // Vietnamese citizen ID: 12 digits starting with 0
	KindCard   = "card"  // payment card number that passes the Luhn check
	KindIPv4   = "ipv4"
)

// CanaryMode says what to do when the canary shows up in the output.
type CanaryMode string

const (
	CanaryOff    CanaryMode = "off"    // no canary is injected
	CanaryBlock  CanaryMode = "block"  // the response is refused
	CanaryRedact CanaryMode = "redact" // the canary is replaced and the response goes on
)

// Config is the output guard's behaviour. The zero value strips every image and
// every link (the allowlist is empty) and does nothing else.
type Config struct {
	// LinkAllowlist holds hosts whose images and links are kept. A host matches
	// itself and its subdomains. Only http and https URLs can match.
	LinkAllowlist []string
	RedactPII     bool // email, phone, CCCD and card numbers
	RedactIPv4    bool // also IPv4 addresses; needs RedactPII
	Canary        CanaryMode
	// DropReasoning removes the reasoning fields some upstreams (Ollama, vLLM)
	// send next to the content, instead of guarding them like the content.
	DropReasoning bool
	// PassUnknownBlocks passes content blocks of a Messages API response, and
	// output items, content parts and stream events of a Responses API
	// response, whose type the guard does not know on unchanged and unchecked
	// (OUTPUT_UNKNOWN_BLOCKS=pass). Off, the default: such a response is
	// refused (ErrUncheckable).
	PassUnknownBlocks bool
}

// Counts is how many findings of each kind were acted on. It never holds content.
type Counts map[string]int

func (c Counts) add(other Counts) {
	for k, v := range other {
		c[k] += v
	}
}

// Total is the number of findings of all kinds.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Guard holds a validated Config. It is safe for concurrent use.
type Guard struct {
	cfg   Config
	hosts []string
}

// New returns a Guard for cfg.
func New(cfg Config) *Guard {
	g := &Guard{cfg: cfg}
	for _, h := range cfg.LinkAllowlist {
		if h = strings.Trim(strings.ToLower(strings.TrimSpace(h)), "."); h != "" {
			g.hosts = append(g.hosts, h)
		}
	}
	if cfg.Canary == "" {
		g.cfg.Canary = CanaryOff
	}
	return g
}

// Config returns the guard's configuration.
func (g *Guard) Config() Config { return g.cfg }

// NewCanary returns a fresh random token for one request.
func NewCanary() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "PS-CANARY-" + strings.ToUpper(hex.EncodeToString(buf)), nil
}

// Scanner applies the guard to one request's output. canary may be empty.
type Scanner struct {
	g      *Guard
	canary string
}

// ForRequest returns a Scanner for one request.
func (g *Guard) ForRequest(canary string) *Scanner {
	if g.cfg.Canary == CanaryOff {
		canary = ""
	}
	return &Scanner{g: g, canary: canary}
}

// Text guards a complete text and adds what it did to counts.
func (s *Scanner) Text(text string, counts Counts) string {
	st := s.NewStream()
	out := st.Write(text) + st.Flush()
	counts.add(st.Counts)
	return out
}

func marker(kind string) string { return "[REDACTED:" + kind + "]" }

// span is one change: text[start:end] becomes repl. It counts one finding of
// kind (none when empty) plus counts, the findings inside a removed link.
type span struct {
	start, end int
	repl       string
	kind       string
	counts     Counts
}

// addSpan counts what a span acts on.
func (c Counts) addSpan(sp span) {
	if sp.kind != "" {
		c[sp.kind]++
	}
	c.add(sp.counts)
}

var (
	// An inline image or link. The URL may hold one level of balanced
	// parentheses, as Wikipedia URLs do, and may be followed by a title. In
	// angle brackets it may hold spaces. The captured URL keeps its brackets;
	// allowed strips them.
	mdURL  = `(<[^<>\n]*>|(?:[^\s()<>]|\([^\s()<>]*\))*)(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?\s*\)`
	mdFull = `(!?)\[([^\[\]\n]{0,1000})\]\(\s*` + mdURL
	mdTail = `\]\(\s*` + mdURL
	// The two run anchored, at the "](" each of their matches holds
	// (mdMatches); the groups are those of mdFull and mdTail.
	mdFullAt = regexp.MustCompile(`^(?:` + mdFull + `)`)
	mdTailAt = regexp.MustCompile(`^(?:` + mdTail + `)`)
	// A reference definition, also inside a blockquote, with the URL on the
	// same line or the next one.
	refDefRe = regexp.MustCompile(`(?m)^[ \t]{0,3}(?:>[ \t]?)*[ \t]{0,3}\[[^\]\n]{1,1000}\]:[ \t]*` +
		`(?:\n[ \t]*(?:>[ \t]?)*[ \t]*)?(<[^<>\n]*>|[^\s<>]+)[^\n]*$`)
	htmlImgRe = regexp.MustCompile(`(?i)<img\b[^>]*>`)
	// src and srcset, but not data-src: the name must follow a space.
	imgSrcRe  = regexp.MustCompile(`(?i)\s(src|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	bareURLRe = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'\x60\[\]()]+`)

	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24}`)
	cccdRe  = regexp.MustCompile(`0\d{11}`)
	phoneRe = regexp.MustCompile(`(?:\+84|84|0)[ .\-]?(?:[35789]\d|2\d\d)(?:[ .\-]?\d){7}`)
	ipv4Re  = regexp.MustCompile(`(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}`)

	imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
		".svg": true, ".bmp": true, ".ico": true, ".avif": true, ".tif": true, ".tiff": true}
)

// allowed reports whether raw is an http or https URL to an allowlisted host.
func (g *Guard) allowed(raw string) bool {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") {
		raw = raw[1 : len(raw)-1]
	}
	if strings.ContainsAny(raw, " \t\n") {
		return false // a URL with spaces is not a plain link to a known host
	}
	u := parseURL(raw)
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return false
	}
	for _, h := range g.hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// imgAllowed reports whether an <img> tag loads only from allowlisted hosts:
// it needs at least one src or srcset, and every URL in them must be allowed.
func (g *Guard) imgAllowed(tag string) bool {
	found := false
	for _, m := range imgSrcRe.FindAllStringSubmatch(tag, -1) {
		value := m[2] + m[3] + m[4] // only one of the three forms matched
		var urls []string
		if strings.EqualFold(m[1], "srcset") {
			for _, candidate := range strings.Split(value, ",") {
				if fields := strings.Fields(candidate); len(fields) > 0 {
					urls = append(urls, fields[0])
				}
			}
		} else {
			urls = []string{value}
		}
		for _, u := range urls {
			found = true
			if !g.allowed(u) {
				return false
			}
		}
	}
	return found
}

func parseURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "//"):
		raw = "https:" + raw
	case len(raw) >= 4 && strings.EqualFold(raw[:4], "www."):
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u
}

// spans finds every change to make in text. accepted do not overlap and are
// sorted; all also holds candidates that lost to an overlapping one, because a
// stream must not cut through any of them. Findings starting before from are
// ignored: a stream passes the text it already sent as context.
func (s *Scanner) spans(text string, from int) (accepted []span, all []span) {
	g := s.g
	var cands []span // in priority order
	add := func(start, end int, repl, kind string, counts Counts) {
		if start >= from {
			cands = append(cands, span{start: start, end: end, repl: repl, kind: kind, counts: counts})
		}
	}

	// Structure first: removing a whole image also removes whatever it carries.
	// Each pattern runs only when text holds what every match of it must hold,
	// which spares the regular expressions on most text.
	if strings.Contains(text, "](") {
		for _, m := range mdMatches(text, true) {
			if g.allowed(text[m[6]:m[7]]) {
				continue
			}
			if m[3] > m[2] { // the "!" of an image
				add(m[0], m[1], marker(KindImage), KindImage, nil)
				continue
			}
			inner := Counts{}
			add(m[0], m[1], s.inline(text[m[4]:m[5]], inner), KindLink, inner)
		}
		for _, m := range mdMatches(text, false) {
			if !g.allowed(text[m[2]:m[3]]) {
				add(m[0], m[1], "]", KindLink, nil)
			}
		}
	}
	if strings.Contains(text, "]:") {
		for _, m := range refDefRe.FindAllStringSubmatchIndex(text, -1) {
			if !g.allowed(text[m[2]:m[3]]) {
				add(m[0], m[1], "", KindLink, nil)
			}
		}
	}
	if indexFold(text, "<img") >= 0 {
		for _, m := range htmlImgRe.FindAllStringIndex(text, -1) {
			if !g.imgAllowed(text[m[0]:m[1]]) {
				add(m[0], m[1], marker(KindImage), KindImage, nil)
			}
		}
	}
	if hasURLStart(text) {
		for _, m := range bareURLRe.FindAllStringIndex(text, -1) {
			if raw := text[m[0]:m[1]]; isImageWithQuery(raw) && !g.allowed(raw) {
				add(m[0], m[1], marker(KindURL), KindURL, nil)
			}
		}
	}
	for _, m := range s.inlineMatches(text, from) {
		add(m.start, m.end, m.repl, m.kind, m.counts)
	}

	all = cands
	for _, c := range cands {
		overlaps := false
		for _, a := range accepted {
			if c.start < a.end && a.start < c.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			accepted = append(accepted, c)
		}
	}
	// A canary inside a removed span still counts: the model leaked it.
	if s.canary != "" {
		for i := range accepted {
			a := &accepted[i]
			if a.kind != KindCanary && a.counts[KindCanary] == 0 {
				if n := strings.Count(text[a.start:a.end], s.canary); n > 0 {
					a.counts = copyCounts(a.counts)
					a.counts[KindCanary] += n
				}
			}
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })
	return accepted, all
}

func copyCounts(c Counts) Counts {
	out := Counts{}
	out.add(c)
	return out
}

func isImageWithQuery(raw string) bool {
	u := parseURL(raw)
	if u == nil || u.RawQuery == "" {
		return false
	}
	return imageExt[strings.ToLower(path.Ext(u.Path))]
}

// inline applies the canary and personal-data detectors to a piece of text,
// such as the text of a removed link.
func (s *Scanner) inline(text string, counts Counts) string {
	matches := s.inlineMatches(text, 0)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m.start])
		b.WriteString(m.repl)
		counts.addSpan(m)
		last = m.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// inlineMatches returns non-overlapping canary and personal-data spans, sorted.
// Matches starting before from are ignored.
func (s *Scanner) inlineMatches(text string, from int) []span {
	return s.inlineMatchesAcross(text, from, nil)
}

// inlineMatchesAcross is inlineMatches restricted, when joins is not nil, to
// matches that hold one of the positions in joins (sorted) strictly inside
// them: values that a removal put together. Others are left out before
// overlaps are settled, so they cannot hide a joined value.
func (s *Scanner) inlineMatchesAcross(text string, from int, joins []int) []span {
	var cands []span
	add := func(start, end int, kind string) {
		if start >= from && (joins == nil || crosses(joins, start, end)) {
			cands = append(cands, span{start: start, end: end, repl: marker(kind), kind: kind})
		}
	}
	if s.canary != "" {
		for off := 0; ; {
			i := strings.Index(text[off:], s.canary)
			if i < 0 {
				break
			}
			add(off+i, off+i+len(s.canary), KindCanary)
			off += i + len(s.canary)
		}
	}
	if s.g.cfg.RedactPII {
		for _, m := range emailMatches(text) {
			if !emailCharAt(text, m[0]-1) {
				add(m[0], m[1], KindEmail)
			}
		}
		if hasDigit(text) {
			for start := 0; ; {
				run, end := nextDigitRun(text, start)
				if run < 0 {
					break
				}
				for _, card := range findCards(text, run, end) {
					add(card[0], card[1], KindCard)
				}
				start = end
			}
			for _, m := range allBounded(cccdRe, text, digitAt) {
				add(m[0], m[1], KindCCCD)
			}
			for _, m := range allBounded(phoneRe, text, func(t string, i int) bool {
				return digitAt(t, i) || (i >= 0 && i < len(t) && t[i] == '+')
			}) {
				add(m[0], m[1], KindPhone)
			}
			if s.g.cfg.RedactIPv4 {
				for _, m := range allBounded(ipv4Re, text, func(t string, i int) bool {
					return digitAt(t, i) || (i >= 0 && i < len(t) && t[i] == '.' &&
						(digitAt(t, i-1) || digitAt(t, i+1)))
				}) {
					add(m[0], m[1], KindIPv4)
				}
			}
		}
	}
	var out []span
	for _, c := range cands {
		overlaps := false
		for _, a := range out {
			if c.start < a.end && a.start < c.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// crosses reports whether one of the sorted positions in joins lies strictly
// inside start..end.
func crosses(joins []int, start, end int) bool {
	i := sort.SearchInts(joins, start+1)
	return i < len(joins) && joins[i] < end
}

// maxEmail is the longest text emailRe can match: a 64-byte local part, "@",
// up to nine labels of 63 bytes with their dots, a dot and a 24-letter TLD.
const maxEmail = 64 + 1 + 63 + 8*64 + 1 + 24

// emailMatches returns what emailRe.FindAllStringIndex(text, -1) returns, but
// runs the expression only around each "@": a match holds exactly one "@",
// starts at most 64 bytes before it and is at most maxEmail bytes long, so
// the leftmost match from any position either holds the next "@" and lies in
// that window, or starts after that "@".
func emailMatches(text string) [][]int {
	var out [][]int
	for off := 0; ; {
		at := strings.IndexByte(text[off:], '@')
		if at < 0 {
			return out
		}
		at += off
		lo, hi := max(off, at-64), min(len(text), at+maxEmail)
		m := emailRe.FindStringIndex(text[lo:hi])
		if m == nil || lo+m[0] > at {
			off = at + 1 // no address holds this "@"
			continue
		}
		out = append(out, []int{lo + m[0], lo + m[1]})
		off = lo + m[1]
	}
}

// nextDigitRun finds the first run of digits from start on, with single spaces
// or dashes between them, as the expression \d(?:[ \-]?\d)* would; -1 when
// there is none.
func nextDigitRun(text string, start int) (int, int) {
	i := start
	for i < len(text) && !isDigit(text[i]) {
		i++
	}
	if i == len(text) {
		return -1, -1
	}
	run := i
	for i++; i < len(text); {
		switch {
		case isDigit(text[i]):
			i++
		case (text[i] == ' ' || text[i] == '-') && i+1 < len(text) && isDigit(text[i+1]):
			i += 2
		default:
			return run, i
		}
	}
	return run, i
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

// indexFold is strings.Index for an ASCII, lower-case sub, ignoring the case
// of s. sub must start with a lower-case letter or another byte that has bit
// 0x20 set (such as "<"): s[i]|0x20 is then a quick test of its first byte.
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i]|0x20 == sub[0] && hasPrefixFold(s[i:], sub) {
			return i
		}
	}
	return -1
}

// lastIndexFold is strings.LastIndex for sub as in indexFold.
func lastIndexFold(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i]|0x20 == sub[0] && hasPrefixFold(s[i:], sub) {
			return i
		}
	}
	return -1
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for j := 0; j < len(prefix); j++ {
		c := s[j]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[j] {
			return false
		}
	}
	return true
}

// hasURLStart reports whether s may hold a match of bareURLRe, which starts
// with "http://", "https://" or "www.", in any case.
func hasURLStart(s string) bool {
	return strings.Contains(s, "://") || indexFold(s, "www.") >= 0
}

func digitAt(t string, i int) bool { return i >= 0 && i < len(t) && t[i] >= '0' && t[i] <= '9' }

func emailCharAt(t string, i int) bool {
	if i < 0 || i >= len(t) {
		return false
	}
	c := t[i]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._%+-", c) >= 0
}

// allBounded finds matches of re whose neighbours are not part of a longer
// token. A rejected match is retried one byte later, so "123 0901234567" still
// finds the phone number. re must only match within a numeric run (the citizen
// ID, phone and IPv4 expressions do), so it runs on the runs alone.
func allBounded(re *regexp.Regexp, text string, inToken func(string, int) bool) [][]int {
	var out [][]int
	for from := 0; ; {
		run, end := nextNumericRun(text, from)
		if run < 0 {
			return out
		}
		for off := run; off < end; {
			m := re.FindStringIndex(text[off:end])
			if m == nil {
				break
			}
			start, stop := off+m[0], off+m[1]
			if !inToken(text, start-1) && !inToken(text, stop) {
				out = append(out, []int{start, stop})
				off = stop
				continue
			}
			off = start + 1
		}
		from = end
	}
}

// nextNumericRun finds the first numeric run from start on (numericRunStart
// describes one); -1 when there is none.
func nextNumericRun(text string, start int) (int, int) {
	i := start
	for i < len(text) && !isDigit(text[i]) && (text[i] != '+' || i+1 == len(text) || !isDigit(text[i+1])) {
		i++
	}
	if i == len(text) {
		return -1, -1
	}
	run := i
	if text[i] == '+' {
		i++
	}
	for i++; i < len(text); {
		switch {
		case isDigit(text[i]):
			i++
		case numSep(text[i]) && i+1 < len(text) && isDigit(text[i+1]):
			i += 2
		default:
			return run, i
		}
	}
	return run, i
}

// mdMatches returns what an unanchored mdFull (full) or mdTail expression's
// FindAllStringSubmatchIndex(text, -1) returns, running the anchored one only
// where a match can start. Every match holds "](": for mdTail it starts there;
// for mdFull the first "](" ends the link text, which holds no brackets or
// line breaks, so the match starts at the "[" before it (or the "!" before
// that), at most maxLinkText+1 bytes back.
func mdMatches(text string, full bool) [][]int {
	var out [][]int
	for off := 0; ; {
		p := strings.Index(text[off:], "](")
		if p < 0 {
			return out
		}
		p += off
		start, re := p, mdTailAt
		if full {
			re = mdFullAt
			lo := max(off, p-maxLinkText-1)
			q := strings.LastIndexAny(text[lo:p], "[]\n")
			if q < 0 || text[lo+q] != '[' {
				off = p + 1
				continue
			}
			start = lo + q
			if start > off && text[start-1] == '!' {
				start--
			}
		}
		m := re.FindStringSubmatchIndex(text[start:])
		if m == nil {
			off = p + 1
			continue
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += start
			}
		}
		out = append(out, m)
		off = m[1]
	}
}

// findCards looks in the digit run text[start:end] (digits with single spaces
// or dashes between them) for group-aligned stretches of 13 to 19 digits that
// pass the Luhn check. It takes the leftmost such stretch, the longest one that
// starts there, then goes on after it, so a run holding several cards yields
// them all.
func findCards(text string, start, end int) [][2]int {
	run := text[start:end]
	type group struct{ start, end, digits int }
	var groups []group
	gs := 0
	for i := 0; i <= len(run); i++ {
		if i == len(run) || run[i] == ' ' || run[i] == '-' {
			groups = append(groups, group{gs, i, i - gs})
			gs = i + 1
		}
	}
	var out [][2]int
	for i := 0; i < len(groups); i++ {
		best := -1
		digits := 0
		for j := i; j < len(groups); j++ {
			digits += groups[j].digits
			if digits > 19 {
				break
			}
			if digits >= 13 && luhn(run[groups[i].start:groups[j].end]) {
				best = j
			}
		}
		if best >= 0 {
			out = append(out, [2]int{start + groups[i].start, start + groups[best].end})
			i = best
		}
	}
	return out
}

func luhn(s string) bool {
	sum, n, double := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		n++
	}
	return n >= 13 && sum%10 == 0
}
