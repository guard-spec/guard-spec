package sanitizer

import (
	"regexp"
	"strings"
)

// HiddenMarker and HiddenEndMarker enclose content that HTML hides from the
// reader: an element styled or flagged as hidden, or an HTML comment. The
// text inside is kept, so a hidden instruction reaches the detectors (and the
// model) as "[hidden] Ignore all previous instructions ... [/hidden]" instead
// of disappearing (comments) or losing the fact that it was hidden (styled
// elements). L1 rules ii.hidden.* key on the markers. A client that types a
// marker itself only raises its own score.
const (
	HiddenMarker    = "[hidden]"
	HiddenEndMarker = "[/hidden]"
)

var (
	// htmlComment matches a comment; bluemonday would drop its text.
	htmlComment = regexp.MustCompile(`(?s)<!--(.*?)(?:-->|$)`)
	// openTag matches an opening tag with attributes; group 1 is the name.
	openTag = regexp.MustCompile(`(?i)<([a-z][a-z0-9-]*)\s[^<>]*>`)
	// hiddenAttr matches the attributes and styles that hide an element's
	// content. Colors only count when text and background are both white, or
	// the text is transparent.
	hiddenAttr = regexp.MustCompile(`(?i)` +
		`display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|` +
		`font-size\s*:\s*0*(?:\.0+)?(?:px|pt|em|rem|%|vw|vh)?\s*(?:!important\s*)?(?:[;"']|$)|` +
		`opacity\s*:\s*0*(?:\.0+)?\s*(?:!important\s*)?(?:[;"']|$)|` +
		`color\s*:\s*transparent|` +
		`(?:left|top|text-indent)\s*:\s*-\d{3,}(?:px|em)|` +
		`(?:height|width|max-height|max-width)\s*:\s*0*(?:\.0+)?(?:px)?\s*;[^"'>]*overflow\s*:\s*hidden|` +
		`aria-hidden\s*=\s*["']?true|` +
		`class\s*=\s*["'](?:[^"']*\s)?(?:hidden|d-none|invisible|sr-only|visually-hidden)[\s"']|` +
		`\shidden(?:\s*=\s*["']?(?:hidden|true|["']))?(?:\s|/?>)`)
	whiteText = regexp.MustCompile(`(?i)(?:^|[;"'\s])color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)`)
	whiteBack = regexp.MustCompile(`(?i)background(?:-color)?\s*:\s*(?:#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)`)
	anyTag    = regexp.MustCompile(`(?i)<(/?)([a-z][a-z0-9-]*)(?:\s[^<>]*)?(/?)>`)
	voidTags  = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
		"img": true, "input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true}
)

const (
	hiddenOpen  = " " + HiddenMarker + " "
	hiddenClose = " " + HiddenEndMarker + " "
	// maxHiddenElements bounds the work on hostile markup; later hidden
	// elements are left to the HTML strip unmarked.
	maxHiddenElements = 256
)

// markHidden encloses hidden content in the markers and reports whether
// there was any.
func markHidden(s string) (string, bool) {
	if !strings.Contains(s, "<") {
		return s, false
	}
	found := false
	s = htmlComment.ReplaceAllStringFunc(s, func(m string) string {
		inner := htmlComment.FindStringSubmatch(m)[1]
		if strings.TrimSpace(inner) == "" {
			return " "
		}
		found = true
		return hiddenOpen + inner + hiddenClose
	})
	var b strings.Builder
	for n := 0; ; n++ {
		loc := nextHidden(s)
		if loc == nil || n == maxHiddenElements {
			b.WriteString(s)
			break
		}
		found = true
		name := strings.ToLower(s[loc[2]:loc[3]])
		b.WriteString(s[:loc[0]])
		rest := s[loc[1]:]
		if voidTags[name] || strings.HasSuffix(s[loc[0]:loc[1]], "/>") {
			s = rest // no content to mark
			continue
		}
		end, closeLen := matchingClose(rest, name)
		b.WriteString(hiddenOpen)
		if end < 0 {
			b.WriteString(rest)
			b.WriteString(hiddenClose)
			break
		}
		// Hidden elements inside are covered already; the HTML strip removes their tags.
		b.WriteString(rest[:end])
		b.WriteString(hiddenClose)
		s = rest[end+closeLen:]
	}
	return b.String(), found
}

// nextHidden finds the first opening tag that hides its content.
func nextHidden(s string) []int {
	off := 0
	for {
		loc := openTag.FindStringSubmatchIndex(s[off:])
		if loc == nil {
			return nil
		}
		for i := range loc {
			loc[i] += off
		}
		tag := s[loc[0]:loc[1]]
		if hiddenAttr.MatchString(tag) || (whiteText.MatchString(tag) && whiteBack.MatchString(tag)) {
			return loc
		}
		off = loc[1]
	}
}

// matchingClose returns the offset and length of the close tag that ends the
// element named name whose content starts s, counting nested elements of the
// same name; -1 when it is never closed.
func matchingClose(s, name string) (int, int) {
	depth := 1
	for _, m := range anyTag.FindAllStringSubmatchIndex(s, -1) {
		if !strings.EqualFold(s[m[4]:m[5]], name) {
			continue
		}
		closing := m[3] > m[2]
		selfClosing := m[7] > m[6]
		switch {
		case closing:
			depth--
			if depth == 0 {
				return m[0], m[1] - m[0]
			}
		case !selfClosing:
			depth++
		}
	}
	return -1, 0
}
