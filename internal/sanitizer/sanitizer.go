package sanitizer

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Report carries signals from the sanitizer for downstream CEL policy evaluation.
type Report struct {
	HadTagChars   bool    // Unicode tag block chars (E0000-E007F) were present
	HadBidi       bool    // bidi control chars were present
	HadANSI       bool    // ANSI escape sequences were present
	HadFakeMarker bool    // input contained our datamarking tokens
	HadHiddenHTML bool    // HTML hid some content (see HiddenMarker); a signal, not an anomaly
	HomoglyphRisk bool    // skeleton analysis found confusable characters
	AnomalyScore  float32 // 0-1 composite signal
	BytesRemoved  int
}

var crlf = strings.NewReplacer("\r\n", "\n", "\r", "\n")

// maxCleanPasses bounds how many cleaning passes the scan view may take: one
// per layer of entity encoding, plus one to find the text stable.
const maxCleanPasses = 8

// Result is what Clean makes of a text.
type Result struct {
	// Scan is the text the detectors read (Sanitize): normalized, entities
	// decoded, hidden HTML marked, tags reduced to the text of their
	// attributes, the content of every element kept.
	Scan string
	// Forward is the text the gateway sends upstream: the input with only the
	// characters a reader cannot see removed (invisible and bidi characters,
	// ANSI escapes, control characters) and spoofed marker tokens. Markup,
	// code, entities, line endings and the Unicode form are left as written,
	// so a prompt about HTML or JSX reaches the model intact; everything in it
	// was read by the detectors through Scan.
	Forward string
	Report  Report
}

// Clean returns both views of a text. Call it where the text is forwarded;
// Sanitize where it is only scored.
func Clean(input string) (Result, error) {
	scan, report, err := Sanitize(input)
	if err != nil {
		return Result{}, err
	}
	return Result{Scan: scan, Forward: forward(input, report.HadFakeMarker), Report: report}, nil
}

// forward removes what a reader cannot see and spoofed markers, and nothing
// else. The input is valid UTF-8 (Sanitize checked it). When the scan view
// found a spoofed marker, the text is NFKC-normalized first, so a fullwidth
// or compatibility spelling of one is removed too.
func forward(s string, hadMarker bool) string {
	if hadMarker {
		if n, _, err := transform.String(norm.NFKC, s); err == nil {
			s = n
		}
	}
	s, _, _ = stripInvisible(s)
	s, _ = stripANSI(s)
	s = stripControls(s)
	s, _ = stripMarkers(s)
	return s
}

// Sanitize applies the full pipeline and returns the scan view (Result.Scan)
// and the report. Order is security-critical: do not reorder steps.
// Call this before passing text to the ML inference layer.
func Sanitize(input string) (string, Report, error) {
	var report Report

	// 1. Validate UTF-8 — reject lone surrogates
	if !utf8.ValidString(input) {
		return "", report, fmt.Errorf("invalid UTF-8 sequence")
	}

	// 2-6. Repeat until stable: decoding an HTML entity can reintroduce anything
	// an earlier step removed (e.g. &#xFE01; or &lt;b&gt;).
	stripped := input
	stable := false
	for i := 0; i < maxCleanPasses && !stable; i++ {
		next, err := cleanPass(stripped, &report)
		if err != nil {
			return "", report, err
		}
		stable = next == stripped
		stripped = next
	}
	if !stable {
		return "", report, fmt.Errorf("input not stable after %d cleaning passes (nested entity encoding)", maxCleanPasses)
	}

	// 7. Homoglyph detection — signal only, do not rewrite.
	report.HomoglyphRisk = checkHomoglyphs(stripped)

	// 8. Spotlighting is no longer applied here: the gateway marks untrusted
	// content itself when SPOTLIGHT is set (package indirect). Spoofed markers,
	// ours or the old [DATA] tokens, were removed in every cleaning pass, so
	// the text holds none of them.
	report.BytesRemoved = len(input) - len(stripped)
	report.AnomalyScore = computeAnomaly(report)

	return stripped, report, nil
}

// cleanPass runs one round of the transforming steps and accumulates signals.
func cleanPass(s string, report *Report) (string, error) {
	// 2. NFKC normalization: decompose ligatures, fullwidth, etc.
	// Must run before stripping — some targets only appear after decomposition.
	normalized, _, err := transform.String(norm.NFKC, s)
	if err != nil {
		return "", fmt.Errorf("NFKC: %w", err)
	}

	// 3. Strip Default_Ignorable_Code_Point chars. Must run before ANSI so a
	// zero-width char cannot split an escape sequence.
	stripped, hadTag, hadBidi := stripInvisible(normalized)
	report.HadTagChars = report.HadTagChars || hadTag
	report.HadBidi = report.HadBidi || hadBidi

	// 4. Strip ANSI escape sequences (in ansi.go, same package).
	// Must run before step 5, which would remove ESC and leave the payload.
	stripped, hadANSI := stripANSI(stripped)
	report.HadANSI = report.HadANSI || hadANSI

	// 5. Strip remaining control chars.
	stripped = stripControls(stripped)

	// 6a. Content a browser would hide (display:none, visibility:hidden,
	// font-size:0, white-on-white, aria-hidden, the hidden attribute, HTML
	// comments) is kept and prefixed with HiddenMarker, so the detectors and
	// the model see that it was hidden instead of losing that signal in step 6.
	stripped, hadHidden := markHidden(stripped)
	report.HadHiddenHTML = report.HadHiddenHTML || hadHidden

	// 6. Tags: each one is replaced by the text of its attributes (stripTags,
	// html.go); the content of every element, script and style included, is
	// kept. Then one layer of entities is decoded.
	stripped = html.UnescapeString(stripTags(stripped))
	// Line endings as an HTML parser reads them (CRLF and CR become LF), as
	// the scan view always had them.
	stripped = crlf.Replace(stripped)

	// 6b. Remove spoofed datamarking tokens. This runs inside the loop because
	// removing one can join its neighbours into a tag or entity that the steps
	// above must see: "<[DATA]script>" becomes "<script>".
	stripped, hadMarker := stripMarkers(stripped)
	report.HadFakeMarker = report.HadFakeMarker || hadMarker
	return stripped, nil
}

// markerPattern matches our marker tokens, tolerating case and spacing: the
// legacy [DATA] and [/DATA], and the spotlighting boundary tags
// <<untrusted-…>> and <</untrusted-…>> (package indirect). Text from a client
// must never carry one, or it could close the data block it sits in.
var markerPattern = regexp.MustCompile(`(?i)\[\s*/?\s*DATA\s*\]|<<\s*/?\s*untrusted-[0-9a-z]*\s*>>`)

// stripMarkers removes marker tokens until none remain, because removing one
// can join its neighbours into a new one: "[/DA[DATA]TA]".
func stripMarkers(s string) (string, bool) {
	found := false
	for markerPattern.MatchString(s) {
		found = true
		s = markerPattern.ReplaceAllString(s, "")
	}
	return s, found
}

// flagSequence matches an emoji tag sequence such as the flag of England.
var flagSequence = regexp.MustCompile(`\x{1F3F4}[\x{E0030}-\x{E0039}\x{E0061}-\x{E007A}]{2,6}\x{E007F}`)

// isIgnorable reports whether r is Default_Ignorable_Code_Point or private use.
// Format chars cover the Tags block, zero-width chars, bidi controls, WJ, BOM and SHY.
func isIgnorable(r rune) bool {
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Co, r) ||
		(unicode.Is(unicode.Cf, r) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r))
}

// stripInvisible removes ignorable chars and reports tag and bidi chars.
// Valid flag sequences reduce to the base emoji without raising the tag signal.
func stripInvisible(s string) (result string, hadTag bool, hadBidi bool) {
	s = flagSequence.ReplaceAllString(s, "\U0001F3F4")
	t := runes.Remove(runes.Predicate(func(r rune) bool {
		if r >= 0xE0000 && r <= 0xE007F {
			hadTag = true
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			hadBidi = true
		}
		return isIgnorable(r)
	}))
	result, _, _ = transform.String(t, s)
	return
}

// stripControls removes C0/C1 controls, preserving tab, LF and CR.
func stripControls(s string) string {
	t := runes.Remove(runes.Predicate(func(r rune) bool {
		return unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r'
	}))
	result, _, _ := transform.String(t, s)
	return result
}

// script is a Unicode script group used for homoglyph detection.
type script uint8

const (
	scriptOther    script = iota
	scriptLatin           // 'a' U+0061
	scriptCyrillic        // 'а' U+0430  — visually identical to Latin 'a'
	scriptGreek           // 'ο' U+03BF  — visually identical to Latin 'o'
	scriptArmenian
	scriptGeorgian
)

func scriptOf(r rune) script {
	switch {
	case unicode.Is(unicode.Latin, r):
		return scriptLatin
	case unicode.Is(unicode.Cyrillic, r):
		return scriptCyrillic
	case unicode.Is(unicode.Greek, r):
		return scriptGreek
	case unicode.Is(unicode.Armenian, r):
		return scriptArmenian
	case unicode.Is(unicode.Georgian, r):
		return scriptGeorgian
	default:
		return scriptOther
	}
}

// checkHomoglyphs implements UTS #39 §5.1 mixed-script detection.
// It returns true when any word in s contains characters from two or more
// distinct confusable scripts (e.g. Latin + Cyrillic). This is a reliable
// signal for homoglyph substitution attacks: visually identical characters
// from different scripts (Cyrillic 'а' for Latin 'a') are used to evade
// keyword filters while remaining undetectable to human readers.
func checkHomoglyphs(s string) bool {
	const nScripts = int(scriptGeorgian) + 1
	var seen [nScripts]bool
	inWord := false

	flush := func() bool {
		defer func() {
			for i := range seen {
				seen[i] = false
			}
			inWord = false
		}()
		count := 0
		for i := int(scriptLatin); i <= int(scriptGeorgian); i++ {
			if seen[i] {
				count++
			}
		}
		return count >= 2
	}

	for _, r := range s {
		if unicode.IsLetter(r) {
			inWord = true
			if sc := scriptOf(r); sc != scriptOther {
				seen[sc] = true
			}
		} else if inWord {
			if flush() {
				return true
			}
		}
	}
	if inWord {
		return flush()
	}
	return false
}

func computeAnomaly(r Report) float32 {
	score := float32(0)
	if r.HadTagChars {
		score += 0.6
	}
	if r.HadBidi {
		score += 0.3
	}
	if r.HadANSI {
		score += 0.2
	}
	if r.HomoglyphRisk {
		score += 0.3
	}
	if r.HadFakeMarker {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}
