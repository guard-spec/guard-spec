package indirect

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// Code corroboration (TOOL_CODE_CORROBORATION, on by default).
//
// The L2 classifier scores repetitive structured text (SQL DDL, Dockerfiles,
// YAML, shell, Vietnamese log lines) as an attack: on benign source code,
// configs, diffs and logs read as tool results, about a third of the
// requests were refused (RF-476b4d30). For untrusted text only (tool results
// and documents, never user, system or tool-description text), a chunk that
// looks like code or a log keeps its fused score only when another layer
// agrees:
//
//   - L1 fired a rule with a raw score of at least corroborationL1Raw (0.5),
//     which includes every decisive rule; or
//   - L3 scored at least corroborationL3 (0.6, calibrated); or
//   - a floor applied (a decisive L1 verdict at the L1 floor, or the org's
//     own block exemplar).
//
// Otherwise its score falls to the larger of the calibrated L1 and L3 scores,
// both below 0.6 then, so the chunk no longer blocks. Without L2 (no models)
// nothing changes. The cost: an injection hidden in code that only L2
// catches gets through (see CHANGELOG 0.4.2 for the measured numbers).

const (
	corroborationL1Raw = 0.5
	corroborationL3    = 0.6
	// CodeCorroborationRule is added to the rules of a chunk whose score
	// was lowered.
	CodeCorroborationRule = "indirect.code_uncorroborated"
	// codeMinLines and codeLineShare: a chunk is code-like when it has at
	// least codeMinLines non-blank lines and at least codeLineShare of them
	// look like code or log lines.
	codeMinLines  = 6
	codeLineShare = 0.6
)

// corroborationL1 is corroborationL1Raw on the calibrated scale of Detail.L1.
var corroborationL1 = fusion.DefaultL1Calibration.Apply(corroborationL1Raw)

// ws is Python's \s for str: the ASCII whitespace with \v, the
// information separators, NEL and the Unicode separators.
const ws = `[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]`

// codeLine matches a line that looks like code, configuration, a diff, a
// stack frame or a log line. Each alternative is anchored to one line:
var codeLine = regexp.MustCompile(strings.NewReplacer(`\s`, ws, `\d`, `\p{Nd}`).Replace(
	`[;{}()\[\],]\s*$` + // ends like a statement, block or call
		`|^\s*(?:#|//|--|/\*|\*|<!--)` + // a comment line
		`|^\s{2,}\S` + // indented
		`|^\s*[\p{L}\p{N}_.\-"']+\s*[:=]\s` + // key: value, name = value
		`|^\s*(?:\[\d{4}-|\d{4}-\d\d-\d\d|\d{1,3}\.\d{1,3}\.)` + // timestamp or IP address first
		`|^\s*[+\-@]` + // diff line, list item
		`|^\s*(?:at\s|File\s")` + // Java/JS or Python stack frame
		`|^\s*[A-Z][A-Z_ ]+\s`)) // SQL or Dockerfile keyword

// CodeLike reports whether text looks like source code, configuration, a
// diff, a stack trace or a log: at least six non-blank lines, 60% of them
// matching codeLine. Prose, e-mails and chat do not: their lines end in
// words and full stops.
func CodeLike(text string) bool {
	n, code := 0, 0
	for _, line := range splitLines(text) {
		if strings.TrimFunc(line, isSpace) == "" {
			continue
		}
		n++
		if codeLine.MatchString(line) {
			code++
		}
	}
	return n >= codeMinLines && float64(code) >= codeLineShare*float64(n)
}

func isSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// splitLines splits like Python's str.splitlines (no line keeps its break).
func splitLines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	b := 0 // byte offset of rs[i]
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		w := len(string(r))
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:b])
			if r == '\r' && i+1 < len(rs) && rs[i+1] == '\n' {
				i++
				b++
			}
			start = b + w
		}
		b += w
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// corroborated reports whether a layer other than L2 supports the score.
func corroborated(d *inference.Detail) bool {
	if d.Floor > 0 || d.L3 >= corroborationL3 {
		return true
	}
	if d.L1 < corroborationL1 {
		return false
	}
	for _, r := range d.Rules {
		if !strings.HasPrefix(r, "l2:") && !strings.HasPrefix(r, "l3:") && !strings.HasPrefix(r, "fusion.") {
			return true // an L1 rule fired
		}
	}
	return false
}

// CorroborateCode is the inference.ChunkAdjust of code corroboration.
func CorroborateCode(chunk string, s inference.Score) inference.Score {
	d := s.Detail
	if d == nil || d.L2 == fusion.Missing || corroborated(d) {
		return s
	}
	limit := max(d.L1, d.L3, 0)
	if float64(s.Confidence) <= limit || !CodeLike(chunk) {
		return s
	}
	nd := *d
	nd.Rules = append(append([]string(nil), d.Rules...), CodeCorroborationRule)
	s.Detail = &nd
	s.Confidence = float32(limit)
	if limit < minCategoryScore {
		nd.Category = ""
		s.Label = "BENIGN"
	}
	return s
}
