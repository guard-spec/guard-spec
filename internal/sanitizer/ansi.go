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

// MCP signal names returned by MCPSignals besides the matched phrases.
const (
	MCPSignalLong      = "long_description" // longer than mcpMaxDescription bytes
	MCPSignalInvisible = "invisible_chars"  // Unicode tag or bidi control characters
)

// mcpMaxDescription is the length above which a description is suspicious.
const mcpMaxDescription = 1500

// CheckMCPDescription returns true if a tool description shows signs of poisoning.
func CheckMCPDescription(description string) bool {
	return len(MCPSignals(description)) > 0
}

// MCPSignals lists the poisoning signals found in a raw (unsanitized) tool
// description: the matched phrases of mcpPoisonSignals, lowercased, then
// MCPSignalLong and MCPSignalInvisible. It is empty for a clean description.
func MCPSignals(description string) []string {
	var found []string
	lower := strings.ToLower(description)
	for _, signal := range mcpPoisonSignals {
		if l := strings.ToLower(signal); strings.Contains(lower, l) {
			found = append(found, l)
		}
	}
	// Structural signals
	if len(description) > mcpMaxDescription {
		found = append(found, MCPSignalLong)
	}
	if _, hadTag, hadBidi := stripInvisible(description); hadTag || hadBidi {
		found = append(found, MCPSignalInvisible)
	}
	return found
}
