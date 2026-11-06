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
	// PassUnknownBlocks passes content blocks of a Messages API response whose
	// type the guard does not know on unchanged and unchecked
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

// span is one change: text[start:end] becomes repl.
type span struct {
	start, end int
	repl       string
	counts     Counts
}

var (
	// An inline image or link. The URL may hold one level of balanced
	// parentheses, as Wikipedia URLs do, and may be followed by a title. In
	// angle brackets it may hold spaces. The captured URL keeps its brackets;
	// allowed strips them.
	mdURL    = `(<[^<>\n]*>|(?:[^\s()<>]|\([^\s()<>]*\))*)(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?\s*\)`
	mdFullRe = regexp.MustCompile(`(!?)\[([^\[\]\n]{0,1000})\]\(\s*` + mdURL)
	mdTailRe = regexp.MustCompile(`\]\(\s*` + mdURL)
	// A reference definition, also inside a blockquote, with the URL on the
	// same line or the next one.
	refDefRe = regexp.MustCompile(`(?m)^[ \t]{0,3}(?:>[ \t]?)*[ \t]{0,3}\[[^\]\n]{1,1000}\]:[ \t]*` +
		`(?:\n[ \t]*(?:>[ \t]?)*[ \t]*)?(<[^<>\n]*>|[^\s<>]+)[^\n]*$`)
	htmlImgRe = regexp.MustCompile(`(?i)<img\b[^>]*>`)
	// src and srcset, but not data-src: the name must follow a space.
	imgSrcRe  = regexp.MustCompile(`(?i)\s(src|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	bareURLRe = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'\x60\[\]()]+`)

	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24}`)
	digitRe = regexp.MustCompile(`\d(?:[ \-]?\d)*`)
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
		if start < from {
			return
		}
		if counts == nil {
			counts = Counts{}
		}
		if kind != "" {
			counts[kind]++
		}
		cands = append(cands, span{start: start, end: end, repl: repl, counts: counts})
	}

	// Structure first: removing a whole image also removes whatever it carries.
	for _, m := range mdFullRe.FindAllStringSubmatchIndex(text, -1) {
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
	for _, m := range mdTailRe.FindAllStringSubmatchIndex(text, -1) {
		if !g.allowed(text[m[2]:m[3]]) {
			add(m[0], m[1], "]", KindLink, nil)
		}
	}
	for _, m := range refDefRe.FindAllStringSubmatchIndex(text, -1) {
		if !g.allowed(text[m[2]:m[3]]) {
			add(m[0], m[1], "", KindLink, nil)
		}
	}
	for _, m := range htmlImgRe.FindAllStringIndex(text, -1) {
		if !g.imgAllowed(text[m[0]:m[1]]) {
			add(m[0], m[1], marker(KindImage), KindImage, nil)
		}
	}
	for _, m := range bareURLRe.FindAllStringIndex(text, -1) {
		if raw := text[m[0]:m[1]]; isImageWithQuery(raw) && !g.allowed(raw) {
			add(m[0], m[1], marker(KindURL), KindURL, nil)
		}
	}
	for _, m := range s.inlineMatches(text, from) {
		add(m.start, m.end, m.repl, "", m.counts)
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
			if a.counts[KindCanary] == 0 {
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
		counts.add(m.counts)
		last = m.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// inlineMatches returns non-overlapping canary and personal-data spans, sorted.
// Matches starting before from are ignored.
func (s *Scanner) inlineMatches(text string, from int) []span {
	var cands []span
	add := func(start, end int, kind string) {
		if start < from {
			return
		}
		cands = append(cands, span{start: start, end: end, repl: marker(kind), counts: Counts{kind: 1}})
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
		for _, m := range emailRe.FindAllStringIndex(text, -1) {
			if !emailCharAt(text, m[0]-1) {
				add(m[0], m[1], KindEmail)
			}
		}
		for _, m := range digitRe.FindAllStringIndex(text, -1) {
			for _, card := range findCards(text, m[0], m[1]) {
				add(card[0], card[1], KindCard)
			}
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
// finds the phone number.
func allBounded(re *regexp.Regexp, text string, inToken func(string, int) bool) [][]int {
	var out [][]int
	for off := 0; off < len(text); {
		m := re.FindStringIndex(text[off:])
		if m == nil {
			break
		}
		start, end := off+m[0], off+m[1]
		if !inToken(text, start-1) && !inToken(text, end) {
			out = append(out, []int{start, end})
			off = end
			continue
		}
		off = start + 1
	}
	return out
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
