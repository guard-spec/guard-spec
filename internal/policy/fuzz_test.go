package policy

import (
	"context"
	"encoding/json"
	"testing"
)

// FuzzJSONASTToCEL checks that converting an untrusted condition never panics,
// and that whatever converts either compiles or is refused by ValidateCEL
// without panicking. A condition that validates must also evaluate.
func FuzzJSONASTToCEL(f *testing.F) {
	for _, s := range []string{
		`{"field":"injection.score","operator":">","value":0.8}`,
		`{"field":"injection.score","operator":">","value":"0.8"}`,
		`{"field":"request.model","operator":"=","value":"gpt-4o"}`,
		`{"field":"request.model","operator":"in","value":["a","b"]}`,
		`{"field":"pii.entities","operator":"contains","value":"EMAIL"}`,
		`{"combinator":"and","rules":[{"field":"anomaly.has_tag_chars","operator":"=","value":true}]}`,
		`{"combinator":"or","not":true,"rules":[{"field":"request.tokens","operator":">=","value":100},{"field":"injection.label","operator":"!=","value":"BENIGN"}]}`,
		`{"combinator":"and","rules":[]}`,
		`{"field":"request.model","operator":"=","value":"\") || true || (\""}`,
		`{"field":"x","operator":"=","value":1}`,
		`{"field":"request.model","operator":"=","value":1,"valueSource":"field"}`,
		`null`, `[]`, `{}`, `"x"`,
	} {
		f.Add([]byte(s))
	}
	eng, err := New()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		expr, err := JSONASTToCEL(raw)
		if err != nil {
			return
		}
		if err := eng.ValidateCEL(expr); err != nil {
			return
		}
		cond, _ := json.Marshal(json.RawMessage(raw))
		p := &Policy{Rules: []Rule{{Name: "fuzz", Action: ActionBlock, Condition: cond}}}
		// Evaluation may fail (for example a cost limit), but must not panic.
		_, _ = eng.Evaluate(context.Background(), p, &Vars{ScoreL1: -1, ScoreL2: -1, ScoreL3: -1})
	})
}

// FuzzValidateRules checks that rule validation never panics, and that a list it
// accepts is accepted again unchanged once stored: IDs are kept, so audit rows
// keep naming the same rule after a policy is re-saved.
func FuzzValidateRules(f *testing.F) {
	for _, s := range []string{
		`[]`,
		`[{"name":"r","action":"block","condition":{"field":"injection.score","operator":">","value":0.9}}]`,
		`[{"name":"r","action":"log","condition":{"combinator":"and","rules":[{"field":"request.model","operator":"=","value":"m"}]}}]`,
		`[{"id":"00000000-0000-0000-0000-000000000001","name":"a","action":"allow","condition":{"field":"anomaly.score","operator":"<","value":1}},
		  {"id":"00000000-0000-0000-0000-000000000001","name":"b","action":"allow","condition":{"field":"anomaly.score","operator":"<","value":1}}]`,
		`[{"name":"r","action":"route","condition":{"field":"injection.score","operator":">","value":0.9}}]`,
		`[{"name":"r","action":"nope"}]`,
		`null`, `{}`, `[null]`,
	} {
		f.Add([]byte(s))
	}
	eng, err := New()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rules, err := eng.ValidateRules(raw)
		if err != nil {
			return
		}
		if len(rules) > MaxRules {
			t.Fatalf("accepted %d rules, limit is %d", len(rules), MaxRules)
		}
		stored, err := json.Marshal(rules)
		if err != nil {
			t.Fatalf("marshal accepted rules: %v", err)
		}
		again, err := eng.ValidateRules(stored)
		if err != nil {
			t.Fatalf("stored rules %s are refused on re-save: %v", stored, err)
		}
		if len(again) != len(rules) {
			t.Fatalf("re-save changed the rule count: %d -> %d", len(rules), len(again))
		}
		for i := range rules {
			if again[i].ID != rules[i].ID || again[i].Action != rules[i].Action {
				t.Fatalf("rule %d changed on re-save: %+v -> %+v", i, rules[i], again[i])
			}
		}
	})
}
