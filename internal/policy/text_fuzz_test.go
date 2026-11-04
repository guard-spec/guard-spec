package policy

import (
	"encoding/json"
	"testing"
)

// FuzzParseCondition checks that untrusted condition text never panics, that
// every refusal is a *ParseError with a position inside the text, and that
// every accepted text gives a tree that validates, formats and parses back to
// itself: format(parse(x)) is stable.
func FuzzParseCondition(f *testing.F) {
	for _, s := range []string{
		`scores.l2 > 0.8 && injection.category == "jailbreak"`,
		`!(scores.l2 > 0.5 || scores.l3 > 0.5)`,
		`scores.l1 > 0.9 || (scores.l2 > 0.5 && scores.l3 > 0.5)`,
		`((scores.l1 > 0.1)) && (request.model in ["a", "b"])`,
		`request.model.contains("gpt") && request.model.startsWith("g") || request.model.endsWith(" ")`,
		`!anomaly.has_bidi && mcp.is_tool_response`,
		`request.tokens >= 100 && request.tenant_id != 'x'`,
		`"x" in pii.entities`,
		`size(request.model) > 1`,
		`scores.l2 > -1e308`,
		`request.model == r"raw\n" || request.model == """tri"ple"""`,
		`[1, 2].exists(x, x > 1)`,
		`a.b.c.d == 1 // comment`,
		`(((`, `)`, `!`, ``,
	} {
		f.Add(s)
	}
	eng, err := New()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		raw, err := ParseCondition(text)
		if err != nil {
			pe, ok := AsParseError(err)
			if !ok {
				t.Fatalf("refusal is not a ParseError: %v", err)
			}
			if pe.Position < 0 || pe.Position > len([]rune(text)) {
				t.Fatalf("position %d outside the text (%d characters)", pe.Position, len([]rune(text)))
			}
			return
		}
		expr, err := JSONASTToCEL(raw)
		if err != nil {
			t.Fatalf("parsed tree %s does not convert: %v", raw, err)
		}
		if err := eng.ValidateCEL(expr); err != nil {
			t.Fatalf("parsed tree %s does not compile: %v", raw, err)
		}
		formatted, err := FormatCondition(raw)
		if err != nil {
			t.Fatalf("parsed tree %s does not format: %v", raw, err)
		}
		again, err := ParseCondition(formatted)
		if err != nil {
			t.Fatalf("formatted text %q does not parse: %v", formatted, err)
		}
		if string(again) != string(raw) {
			t.Fatalf("parse(format(parse(x))) differs\ntext  %q\nfirst %s\nagain %s", text, raw, again)
		}
		if f2, _ := FormatCondition(again); f2 != formatted {
			t.Fatalf("format not stable: %q -> %q", formatted, f2)
		}
		var tree any
		if err := json.Unmarshal(raw, &tree); err != nil {
			t.Fatalf("tree is not JSON: %v", err)
		}
	})
}
