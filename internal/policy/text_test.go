package policy

import (
	"encoding/json"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func mustParse(t *testing.T, text string) json.RawMessage {
	t.Helper()
	raw, err := ParseCondition(text)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	return raw
}

func mustFormat(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	text, err := FormatCondition(raw)
	if err != nil {
		t.Fatalf("format %s: %v", raw, err)
	}
	return text
}

func TestParseCondition(t *testing.T) {
	tests := []struct {
		text, tree, canonical string
	}{
		{`scores.l2 > 0.8`,
			`{"combinator":"and","rules":[{"field":"scores.l2","operator":">","value":0.8}]}`,
			`scores.l2 > 0.8`},
		{`scores.l2 > 0.8 && injection.category == "jailbreak"`,
			`{"combinator":"and","rules":[{"field":"scores.l2","operator":">","value":0.8},{"field":"injection.category","operator":"=","value":"jailbreak"}]}`,
			`scores.l2 > 0.8 && injection.category == "jailbreak"`},
		{`request.tokens >= 100 || anomaly.has_bidi`,
			`{"combinator":"or","rules":[{"field":"request.tokens","operator":">=","value":100},{"field":"anomaly.has_bidi","operator":"=","value":true}]}`,
			`request.tokens >= 100 || anomaly.has_bidi == true`},
		{`scores.l1 > 1`,
			`{"combinator":"and","rules":[{"field":"scores.l1","operator":">","value":1}]}`,
			`scores.l1 > 1.0`},
		{`scores.l3 > -0.5`,
			`{"combinator":"and","rules":[{"field":"scores.l3","operator":">","value":-0.5}]}`,
			`scores.l3 > -0.5`},
		{`request.model in ["a", "b"]`,
			`{"combinator":"and","rules":[{"field":"request.model","operator":"in","value":["a","b"]}]}`,
			`request.model in ["a", "b"]`},
		{`request.model.contains("gpt") && request.model.startsWith("g") && request.model.endsWith("o")`,
			`{"combinator":"and","rules":[{"field":"request.model","operator":"contains","value":"gpt"},{"field":"request.model","operator":"beginsWith","value":"g"},{"field":"request.model","operator":"endsWith","value":"o"}]}`,
			`request.model.contains("gpt") && request.model.startsWith("g") && request.model.endsWith("o")`},
		{`!(scores.l2 > 0.5 || scores.l3 > 0.5)`,
			`{"combinator":"or","not":true,"rules":[{"field":"scores.l2","operator":">","value":0.5},{"field":"scores.l3","operator":">","value":0.5}]}`,
			`!(scores.l2 > 0.5 || scores.l3 > 0.5)`},
		{`!anomaly.has_bidi`,
			`{"combinator":"and","not":true,"rules":[{"field":"anomaly.has_bidi","operator":"=","value":true}]}`,
			`!(anomaly.has_bidi == true)`},
		// && inside || needs no parentheses and stays a group.
		{`scores.l1 > 0.9 || scores.l2 > 0.5 && scores.l3 > 0.5`,
			`{"combinator":"or","rules":[{"field":"scores.l1","operator":">","value":0.9},{"combinator":"and","rules":[{"field":"scores.l2","operator":">","value":0.5},{"field":"scores.l3","operator":">","value":0.5}]}]}`,
			`scores.l1 > 0.9 || scores.l2 > 0.5 && scores.l3 > 0.5`},
		{`scores.l1 > 0.9 || (scores.l2 > 0.5 && scores.l3 > 0.5)`,
			`{"combinator":"or","rules":[{"field":"scores.l1","operator":">","value":0.9},{"combinator":"and","rules":[{"field":"scores.l2","operator":">","value":0.5},{"field":"scores.l3","operator":">","value":0.5}]}]}`,
			`scores.l1 > 0.9 || scores.l2 > 0.5 && scores.l3 > 0.5`},
		// Parentheses around a run of the same operator keep it a group.
		{`(scores.l1 > 0.1 && scores.l2 > 0.2) && scores.l3 > 0.3`,
			`{"combinator":"and","rules":[{"combinator":"and","rules":[{"field":"scores.l1","operator":">","value":0.1},{"field":"scores.l2","operator":">","value":0.2}]},{"field":"scores.l3","operator":">","value":0.3}]}`,
			`(scores.l1 > 0.1 && scores.l2 > 0.2) && scores.l3 > 0.3`},
		{`(scores.l1 > 0.1 || scores.l2 > 0.2) && scores.l3 > 0.3`,
			`{"combinator":"and","rules":[{"combinator":"or","rules":[{"field":"scores.l1","operator":">","value":0.1},{"field":"scores.l2","operator":">","value":0.2}]},{"field":"scores.l3","operator":">","value":0.3}]}`,
			`(scores.l1 > 0.1 || scores.l2 > 0.2) && scores.l3 > 0.3`},
		{`  ( scores.l1 > 0.1 )  `,
			`{"combinator":"and","rules":[{"combinator":"and","rules":[{"field":"scores.l1","operator":">","value":0.1}]}]}`,
			`(scores.l1 > 0.1)`},
		{`injection.source_role != "user" && request.model == "é\"x"`,
			`{"combinator":"and","rules":[{"field":"injection.source_role","operator":"!=","value":"user"},{"field":"request.model","operator":"=","value":"é\"x"}]}`,
			`injection.source_role != "user" && request.model == "é\"x"`},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			raw := mustParse(t, tt.text)
			if string(raw) != tt.tree {
				t.Errorf("tree\n got %s\nwant %s", raw, tt.tree)
			}
			text := mustFormat(t, raw)
			if text != tt.canonical {
				t.Errorf("format\n got %s\nwant %s", text, tt.canonical)
			}
			again := mustParse(t, text)
			if string(again) != string(raw) {
				t.Errorf("reparse\n got %s\nwant %s", again, raw)
			}
		})
	}
}

func TestParseConditionRefuses(t *testing.T) {
	tests := []struct {
		text, msg string
		pos       int
	}{
		{``, "empty", 0},
		{`scores.l2 >`, "syntax error", 11},
		{`scores.l2 > 0.8 &&`, "syntax error", 18},
		{`nope.field > 1`, "unknown field", 0},
		{`toxicity.score > 0.5`, "removed", 0},
		{`0.5 < scores.l2`, "put the field on the left", 0},
		{`scores.l2 > scores.l1`, "literal", 12},
		{`request.model > "a"`, "only = and !=", 0},
		{`request.model == 1`, "is a string", 17},
		{`scores.l2 == "x"`, "is a number", 13},
		{`request.tokens > 1.5`, "whole number", 17},
		{`anomaly.has_bidi == 1`, "true or false", 20},
		{`scores.l2`, "compare it with a value", 0},
		{`true`, "constant", 0},
		{`size(request.model) > 1`, "function size", 0},
		{`request.model.matches("x")`, "method matches", 14},
		{`request.model.size() > 1`, "method size", 14},
		{`scores.l2 + 1.0 > 2.0`, "operator +", 10},
		{`scores.l2 > 0.5 ? true : false`, "operator", 16},
		{`request.model in []`, "non-empty list", 17},
		{`request.model in ["a", 1]`, "list of strings", 23},
		{`scores.l2 in [1.0]`, "in applies to a string field", 0},
		{`"x" in request.model`, "list field", 0},
		{`has(request.model)`, "function has", 0},
		{`request["model"] == "a"`, "operator", 7},
		{`{"a": 1}.a == 1`, "unsupported", 0},
		{`scores.l2 > 0.5 || scores.l2 > 0.5 &&`, "syntax error", 37},
		{`b"x" == request.model`, "", 0},
		{`request.model == null`, "is a string", 17},
		{strings.Repeat("(", 200) + "scores.l2 > 1.0" + strings.Repeat(")", 200), "", 0},
		{strings.Repeat("scores.l2 > 1.0 && ", 300) + "scores.l2 > 1.0", "longer than", 4096},
	}
	for _, tt := range tests {
		t.Run(tt.text[:min(len(tt.text), 40)], func(t *testing.T) {
			raw, err := ParseCondition(tt.text)
			if err == nil {
				t.Fatalf("accepted: %s", raw)
			}
			pe, ok := AsParseError(err)
			if !ok {
				t.Fatalf("not a ParseError: %v", err)
			}
			if !strings.Contains(pe.Message, tt.msg) {
				t.Errorf("message %q, want it to contain %q", pe.Message, tt.msg)
			}
			if tt.msg != "" && pe.Position != tt.pos {
				t.Errorf("position %d, want %d (%s)", pe.Position, tt.pos, pe.Message)
			}
		})
	}
}

func TestFormatConditionNormalizesBuilderTrees(t *testing.T) {
	tests := []struct{ tree, text string }{
		// The builder sends numbers as strings and lists as comma-separated text.
		{`{"combinator":"and","rules":[{"id":"r1","field":"scores.l2","operator":">","value":"0.80","valueSource":"value"},
		  {"field":"request.model","operator":"in","value":"a, b"}]}`,
			`scores.l2 > 0.8 && request.model in ["a", "b"]`},
		{`{"field":"request.model","operator":"==","value":"m"}`, `request.model == "m"`},
		{`{"combinator":"OR","rules":[{"field":"anomaly.has_bidi","operator":"=","value":"true"}]}`, `anomaly.has_bidi == true`},
		{`{"combinator":"and","rules":[{"combinator":"or","not":true,"rules":[{"field":"scores.l1","operator":"<","value":0.1}]}]}`,
			`!(scores.l1 < 0.1)`},
	}
	for _, tt := range tests {
		got := mustFormat(t, json.RawMessage(tt.tree))
		if got != tt.text {
			t.Errorf("format %s\n got %s\nwant %s", tt.tree, got, tt.text)
		}
		canon, err := CanonicalCondition(json.RawMessage(tt.tree))
		if err != nil {
			t.Fatal(err)
		}
		if parsed := mustParse(t, got); string(parsed) != string(canon) {
			t.Errorf("parse(format(%s))\n got %s\nwant %s", tt.tree, parsed, canon)
		}
	}
	for _, bad := range []string{`{}`, `{"combinator":"and","rules":[]}`, `{"field":"toxicity.score","operator":">","value":1}`,
		`{"field":"scores.l2","operator":"in","value":["a"]}`, `null`} {
		if text, err := FormatCondition(json.RawMessage(bad)); err == nil {
			t.Errorf("format %s = %q, want an error", bad, text)
		}
	}
	if text, err := FormatStoredCondition(json.RawMessage(`{"field":"toxicity.score","operator":">","value":1}`)); err != nil ||
		text != "toxicity.score > 1.0" {
		t.Errorf("stored removed field: %q %v", text, err)
	}
}

// The text form must give the same CEL as the tree it came from: the CEL of
// the parsed tree compiles and means what the text says.
func TestParsedTreeCompilesToTheSameCEL(t *testing.T) {
	e := newEngine(t)
	text := `scores.l2 > 0.8 && injection.category != "benign" || !(request.model in ["a", "b"])`
	raw := mustParse(t, text)
	expr, err := JSONASTToCEL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ValidateCEL(expr); err != nil {
		t.Fatal(err)
	}
	want := `((scores.l2 > 0.8) && (injection.category != "benign")) || (!((request.model in ["a", "b"])))`
	if expr != want {
		t.Errorf("cel\n got %s\nwant %s", expr, want)
	}
}

// A list field ends its leaf with a select ("x" in attrs.categories): the
// field name after the last dot is part of the leaf, so parentheses around
// a group that ends with it still make a group.
func TestParseListFieldInParentheses(t *testing.T) {
	fields := FieldSet{"attrs.score": Double, "attrs.categories": StringList}
	parsed, err := parseCondition(`!((attrs.score > 0.5 && "jailbreak" in attrs.categories)) || ("x" in attrs.categories)`, fields)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"combinator":"or","rules":[{"combinator":"and","not":true,"rules":[{"combinator":"and","rules":[` +
		`{"field":"attrs.score","operator":">","value":0.5},` +
		`{"field":"attrs.categories","operator":"contains","value":"jailbreak"}]}]},` +
		`{"combinator":"and","rules":[{"field":"attrs.categories","operator":"contains","value":"x"}]}]}`
	if string(parsed) != want {
		t.Errorf("parsed\n got %s\nwant %s", parsed, want)
	}
}

// ── Round-trip property ──────────────────────────────────────────────────────

type treeGen struct{ r *rand.Rand }

func (g treeGen) leaf() map[string]any {
	names := make([]string, 0, len(fieldTypes))
	for name := range fieldTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	field := names[g.r.IntN(len(names))]
	strs := []string{"", "a", "gpt-4o", `q"uote`, `back\slash`, "tiếng Việt", "tab\there", "\x01ctl", "✓"}
	str := func() string { return strs[g.r.IntN(len(strs))] }
	switch typeName(fieldTypes[field]) {
	case "double":
		ops := operatorsByType["double"]
		vals := []float64{0, 0.5, -1, 1, 0.123456789, 1e-7, 3}
		return map[string]any{"field": field, "operator": ops[g.r.IntN(len(ops))], "value": vals[g.r.IntN(len(vals))]}
	case "int":
		ops := operatorsByType["int"]
		return map[string]any{"field": field, "operator": ops[g.r.IntN(len(ops))], "value": float64(g.r.IntN(5000) - 100)}
	case "bool":
		ops := operatorsByType["bool"]
		return map[string]any{"field": field, "operator": ops[g.r.IntN(len(ops))], "value": g.r.IntN(2) == 0}
	case "list":
		// "x" in list: contains (in reads the same and is written contains).
		return map[string]any{"field": field, "operator": "contains", "value": str()}
	default:
		ops := operatorsByType["string"]
		op := ops[g.r.IntN(len(ops))]
		if op == "in" {
			n := 1 + g.r.IntN(3)
			items := make([]any, n)
			for i := range items {
				items[i] = str()
			}
			return map[string]any{"field": field, "operator": op, "value": items}
		}
		return map[string]any{"field": field, "operator": op, "value": str()}
	}
}

// group builds the kind of tree the builder produces: groups with an
// and/or combinator, an optional not, and one or more rules.
func (g treeGen) group(depth int) map[string]any {
	n := 1 + g.r.IntN(3)
	rules := make([]any, n)
	for i := range rules {
		if depth > 0 && g.r.IntN(3) == 0 {
			rules[i] = g.group(depth - 1)
		} else {
			rules[i] = g.leaf()
		}
	}
	comb := "and"
	if g.r.IntN(2) == 0 {
		comb = "or"
	}
	out := map[string]any{"combinator": comb, "rules": rules}
	if g.r.IntN(4) == 0 {
		out["not"] = true
	}
	return out
}

func TestFormatParseRoundTripProperty(t *testing.T) {
	e := newEngine(t)
	g := treeGen{r: rand.New(rand.NewPCG(1, 2))}
	for i := 0; i < 3000; i++ {
		tree, err := json.Marshal(g.group(3))
		if err != nil {
			t.Fatal(err)
		}
		canon, err := CanonicalCondition(tree)
		if err != nil {
			t.Fatalf("canonical %s: %v", tree, err)
		}
		text := mustFormat(t, tree)
		parsed := mustParse(t, text)
		if string(parsed) != string(canon) {
			t.Fatalf("parse(format(tree)) differs\ntree   %s\ntext   %s\nparsed %s\ncanon  %s", tree, text, parsed, canon)
		}
		if again := mustFormat(t, parsed); again != text {
			t.Fatalf("format not stable\n%s\n%s", text, again)
		}
		// The text means the same: both trees give CEL that compiles, and the
		// canonical tree's CEL equals the original's.
		want, _ := JSONASTToCEL(tree)
		got, _ := JSONASTToCEL(parsed)
		if err := e.ValidateCEL(got); err != nil {
			t.Fatalf("parsed tree does not compile: %v\n%s", err, got)
		}
		if strings.Count(want, "(") < strings.Count(text, "(") {
			t.Fatalf("format added parentheses: %s -> %s", want, text)
		}
		if !sameMeaning(t, e, tree, parsed) {
			t.Fatalf("meaning changed\ntree   %s\nparsed %s", tree, parsed)
		}
	}
}

// sameMeaning evaluates both conditions on a few inputs.
func sameMeaning(t *testing.T, e *Engine, a, b json.RawMessage) bool {
	t.Helper()
	inputs := []*Vars{
		{},
		{RequestModel: "gpt-4o", RequestTokens: 200, ScoreL1: 0.5, ScoreL2: 1, ScoreL3: -1, InjectionScore: 3,
			InjectionCat: "a", AnomalyHasBidi: true, SourceRole: `q"uote`},
		{RequestModel: "tiếng Việt", ScoreL1: 0.123456789, AnomalyScore: 0.5, IndirectSource: "✓", IsMCPResponse: true},
	}
	for _, v := range inputs {
		da, errA := e.Evaluate(t.Context(), &Policy{ID: uuid.New(), Rules: []Rule{{Action: ActionBlock, Condition: a}}}, v)
		db, errB := e.Evaluate(t.Context(), &Policy{ID: uuid.New(), Rules: []Rule{{Action: ActionBlock, Condition: b}}}, v)
		if errA != nil || errB != nil {
			t.Fatalf("evaluate: %v %v", errA, errB)
		}
		if da.Matched != db.Matched {
			return false
		}
	}
	return true
}
