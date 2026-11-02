package sanitizer

import (
	"regexp"
	"strings"
)

// ANSI escape sequence pattern that correctly handles:
//   - CSI sequences: ESC [ ... final-byte
//   - OSC sequences: ESC ] ... ST (ESC \) or BEL (0x07) or C1 0x9C terminator
//   - Simple ESC sequences
//
// OSC 52 (clipboard write) is unconditionally killed regardless of context.
var ansiPattern = regexp.MustCompile(
	`\x1b\[[0-9;]*[A-Za-z]` + // CSI sequences
		`|\x1b\][^\x1b\x07\x9c]*(?:\x1b\\|\x07|\x9c)` + // OSC sequences (any terminator)
		`|\x1b[\x40-\x5F]` + // Fe sequences (two-char)
		`|\x1b[^[\\]@-Z]` + // other ESC sequences
		`|\x9b[0-9;]*[A-Za-z]` + // C1 CSI (8-bit)
		`|\x9d[^\x9c\x1b\x07]*[\x9c\x1b\x07]`, // C1 OSC (8-bit)
)

// osc52 matches OSC 52 (clipboard write) — kill unconditionally
var osc52 = regexp.MustCompile(`\x1b\]52[^\x1b\x07\x9c]*(?:\x1b\\|\x07|\x9c)`)

func stripANSI(s string) (string, bool) {
	// Kill OSC 52 first (it can masquerade inside other sequences)
	stripped := osc52.ReplaceAllString(s, "")
	stripped = ansiPattern.ReplaceAllString(stripped, "")
	return stripped, stripped != s
}

// MCP tool description signals — Invariant Labs taxonomy
var mcpPoisonSignals = []string{
	"<IMPORTANT>",
	"<SYSTEM>",
	"<INSTRUCTIONS>",
	"do not mention this to the user",
	"~/.ssh",
	"id_rsa",
	"/.env",
	"/etc/shadow",
	"mcp.json",
	"send all emails to",
	"BCC:",
	"VERY VERY important",
	"the tool will not work otherwise",
	"Before using this tool",
}

// CheckMCPDescription returns true if a tool description shows signs of poisoning.
func CheckMCPDescription(description string) bool {
	lower := strings.ToLower(description)
	for _, signal := range mcpPoisonSignals {
		if strings.Contains(lower, strings.ToLower(signal)) {
			return true
		}
	}
	// Structural signals
	if len(description) > 1500 {
		return true
	}
	_, hadTag, hadBidi := stripDangerousRanges(description)
	return hadTag || hadBidi
}
