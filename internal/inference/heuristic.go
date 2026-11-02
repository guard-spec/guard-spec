package inference

import (
	"context"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// heuristicInjectionBackend detects common prompt injection patterns without an ML model.
type heuristicInjectionBackend struct{}

type injPattern struct {
	re     *regexp.Regexp
	signal float32
	label  string
}

var injPatterns []injPattern

func init() {
	// English patterns — raw string literals, compiled once.
	enPats := []struct {
		pat   string
		score float32
		lbl   string
	}{
		{`(?i)\bignore\b.{0,30}\b(all\s+)?(previous|prior|above|former)\b.{0,30}\binstructions?\b`, 0.92, "INSTRUCTION_OVERRIDE"},
		{`(?i)\bforget\b.{0,20}\b(all\s+)?(previous|prior|above)\b.{0,20}\b(instructions?|context|rules?)\b`, 0.90, "INSTRUCTION_OVERRIDE"},
		{`(?i)\bdisregard\b.{0,20}\b(all\s+)?(previous|prior|above)\b.{0,20}\b(instructions?|guidelines?)\b`, 0.90, "INSTRUCTION_OVERRIDE"},
		{`(?i)\boverride\b.{0,20}\b(your\s+)?(instructions?|rules?|guidelines?|constraints?|restrictions?)\b`, 0.88, "INSTRUCTION_OVERRIDE"},
		{`(?i)\b(you\s+are\s+no\s+longer|stop\s+being)\b.{0,30}\b(ai|assistant|helpful|claude|gpt|chatgpt)\b`, 0.88, "PERSONA_OVERRIDE"},
		{`(?i)\bDAN\b.{0,30}\b(do\s+anything\s+now|no\s+restrictions?|jailbreak)\b`, 0.95, "DAN_JAILBREAK"},
		{`(?i)\bdo\s+anything\s+now\b`, 0.93, "DAN_JAILBREAK"},
		{`(?i)\bjailbreak\b.{0,30}\b(mode|activated?|enabled?)\b`, 0.93, "JAILBREAK"},
		{`(?i)\bdeveloper\s+mode\b.{0,30}\b(enabled?|activated?|on)\b`, 0.90, "DEV_MODE"},
		{`(?i)\bgodmode\b|\bgod\s+mode\b`, 0.88, "JAILBREAK"},
		{`(?i)\[START\s+OF\s+(NEW\s+)?PERSONA\]`, 0.95, "PERSONA_INJECTION"},
		{`(?i)\[END\s+OF\s+(NEW\s+)?PERSONA\]`, 0.88, "PERSONA_INJECTION"},
		{`(?i)\bact\s+as\b.{0,20}\b(ai|assistant|dan|gpt|claude|bot|unrestricted)\b`, 0.88, "PERSONA_INJECTION"},
		{`(?i)\byou\s+(are|will\s+be)\s+(now\s+)?(an?\s+)?(ai|dan|gpt|claude|unrestricted|unfiltered|uncensored)`, 0.92, "PERSONA_INJECTION"},
		{`(?i)\bpretend\s+(you\s+are|to\s+be)\b.{0,30}\b(ai|unrestricted|unfiltered|dan|jailbroken)\b`, 0.88, "PERSONA_INJECTION"},
		{`(?i)\bnew\s+persona\b|\bswitch\s+(to\s+)?persona\b`, 0.85, "PERSONA_INJECTION"},
		{`(?i)\b(reveal|print|show|output|repeat|disclose|leak|tell me)\b.{0,30}\b(your\s+)?(system\s+prompt|instructions?|guidelines?|rules?)\b`, 0.92, "PROMPT_EXTRACTION"},
		{`(?i)\bwhat\s+(is|are)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+rules?)\b`, 0.88, "PROMPT_EXTRACTION"},
		{`(?i)\bsystem\s+prompt\b`, 0.72, "PROMPT_EXTRACTION_WEAK"},
		{`(?i)\binitial\s+instructions?\b.{0,20}\b(what|show|reveal|tell)\b`, 0.85, "PROMPT_EXTRACTION"},
		{`(?i)\bno\s+restrictions?\b|\bwithout\s+restrictions?\b|\bunrestricted\b`, 0.85, "NO_RESTRICTIONS"},
		{`(?i)\bunfiltered\b|\buncensored\b|\bunlimited\b.{0,15}\b(access|mode|ai)\b`, 0.85, "NO_RESTRICTIONS"},
		{`(?i)\b(bypass|circumvent|get\s+around)\b.{0,20}\b(filter|restriction|guardrail|safety|censor)\b`, 0.92, "BYPASS_ATTEMPT"},
		{`(?i)\bINSTRUCTION\s*:\s*(ignore|override|disregard)\b`, 0.88, "INDIRECT_INJECTION"},
		{`(?i)\bSYSTEM\s*:\s*(ignore|you\s+are|act\s+as)\b`, 0.88, "INDIRECT_INJECTION"},
		{`(?i)<\s*(INST|SYS|SYSTEM|HUMAN|ASSISTANT)\s*>`, 0.75, "TEMPLATE_INJECTION"},
	}

	// Vietnamese patterns — using regular string literals with \\s and explicit Unicode escapes.
	// \b word boundaries don't work on non-ASCII; .{0,N} guards are used instead.
	viPats := []struct {
		pat   string
		score float32
		lbl   string
	}{
		// "bỏ qua" (ignore) + instructions
		{"(?i)b\u1ecf\\s+qua.{0,20}(h\u01b0\u1edbng\\s+d\u1eabn|ch\u1ec9\\s+th\u1ecb|quy\\s+t\u1eafc)", 0.90, "VI_INSTRUCTION_OVERRIDE"},
		// "hãy đóng vai" / "giả vờ là" / "trở thành"
		{"(?i)h\u00e3y\\s+(\u0111\u00f3ng\\s+vai|gi\u1ea3\\s+v\u1edd\\s+l\u00e0|tr\u1edf\\s+th\u00e0nh)", 0.88, "VI_PERSONA_INJECTION"},
		// "đóng vai" + no-restrictions
		{"(?i)\u0111\u00f3ng\\s+vai.{0,30}(kh\u00f4ng\\s+c\u00f3\\s+gi\u1edbi\\s+h\u1ea1n|kh\u00f4ng\\s+h\u1ea1n\\s+ch\u1ebf)", 0.92, "VI_JAILBREAK"},
		// "không có giới hạn" or "không hạn chế" (no restrictions)
		{"(?i)kh\u00f4ng\\s+(c\u00f3\\s+)?gi\u1edbi\\s+h\u1ea1n|kh\u00f4ng\\s+h\u1ea1n\\s+ch\u1ebf", 0.85, "VI_NO_RESTRICTIONS"},
		// "tiết lộ" (disclose) + system prompt / instructions
		{"(?i)ti\u1ebft\\s+l\u1ed9.{0,30}(system\\s+prompt|h\u01b0\u1edbng\\s+d\u1eabn|ch\u1ec9\\s+th\u1ecb)", 0.92, "VI_PROMPT_EXTRACTION"},
		// Combined no-restrictions + disclose (highest signal)
		{"(?i)(kh\u00f4ng\\s+(c\u00f3\\s+)?gi\u1edbi\\s+h\u1ea1n|kh\u00f4ng\\s+h\u1ea1n\\s+ch\u1ebf).{0,80}(ti\u1ebft\\s+l\u1ed9|system\\s+prompt)", 0.95, "VI_JAILBREAK_EXTRACT"},
		// "từ bỏ"/"quên"/"bỏ qua" + "vai trò/nhiệm vụ/hướng dẫn"
		{"(?i)(t\u1eeb\\s+b\u1ecf|qu\u00ean|b\u1ecf\\s+qua).{0,20}(vai\\s+tr\u00f2|nhi\u1ec7m\\s+v\u1ee5|h\u01b0\u1edbng\\s+d\u1eabn)", 0.88, "VI_INSTRUCTION_OVERRIDE"},
	}

	injPatterns = make([]injPattern, 0, len(enPats)+len(viPats))
	for _, d := range enPats {
		if re, err := regexp.Compile(d.pat); err == nil {
			injPatterns = append(injPatterns, injPattern{re: re, signal: d.score, label: d.lbl})
		}
	}
	for _, d := range viPats {
		if re, err := regexp.Compile(d.pat); err == nil {
			injPatterns = append(injPatterns, injPattern{re: re, signal: d.score, label: d.lbl})
		}
	}
}

// Run implements ModelBackend.
func (h *heuristicInjectionBackend) Run(_ context.Context, text string) ([]Score, error) {
	normalized := normalizeForMatching(text)

	var matched []injPattern
	for _, p := range injPatterns {
		if p.re.MatchString(normalized) {
			matched = append(matched, p)
		}
	}

	if len(matched) == 0 {
		return []Score{{Label: "BENIGN", Confidence: 0.02}}, nil
	}

	best := matched[0]
	for _, m := range matched[1:] {
		if m.signal > best.signal {
			best = m
		}
	}

	score := best.signal
	if len(matched) >= 2 && score < 0.95 {
		score = min32(score+0.05, 0.98)
	}

	return []Score{{Label: best.label, Confidence: score}}, nil
}

// normalizeForMatching applies NFC Unicode normalization, strips datamarking wrappers,
// and collapses whitespace so Vietnamese precomposed chars match regex patterns.
func normalizeForMatching(s string) string {
	s = norm.NFC.String(s)
	s = strings.ReplaceAll(s, "\uE000", "")
	s = strings.ReplaceAll(s, "[DATA]", "")
	s = strings.ReplaceAll(s, "[/DATA]", "")

	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
			}
			prevSpace = true
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return b.String()
}

func min32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}