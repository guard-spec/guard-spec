// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/outputguard"
)

// input.pii.kinds and input.pii.count: rules can log or block on them, with
// the list and number operators.
func TestInputPIIFields(t *testing.T) {
	e := newEngine(t)
	found := &Vars{InputPIIKinds: []string{"email", "phone"}, InputPIICount: 3}
	none := &Vars{}
	tests := []struct {
		condition       string
		onFound, onNone bool
	}{
		{`{"field":"input.pii.count","operator":">","value":0}`, true, false},
		{`{"field":"input.pii.count","operator":">=","value":"3"}`, true, false},
		{`{"field":"input.pii.count","operator":"=","value":0}`, false, true},
		{`{"field":"input.pii.kinds","operator":"contains","value":"email"}`, true, false},
		{`{"field":"input.pii.kinds","operator":"in","value":"phone"}`, true, false},
		{`{"field":"input.pii.kinds","operator":"contains","value":"card"}`, false, false},
		{`{"combinator":"and","not":true,"rules":[{"field":"input.pii.kinds","operator":"contains","value":"cccd"}]}`, true, true},
	}
	for _, tt := range tests {
		for _, action := range []Action{ActionBlock, ActionLog} {
			p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
				ID: uuid.New(), Action: action, Condition: json.RawMessage(tt.condition)}}}
			if _, err := e.ValidateRules(mustJSON(t, p.Rules)); err != nil {
				t.Fatalf("%s %s: new rule refused: %v", tt.condition, action, err)
			}
			for _, c := range []struct {
				vars *Vars
				want bool
			}{{found, tt.onFound}, {none, tt.onNone}} {
				d, err := e.Evaluate(context.Background(), p, c.vars)
				if err != nil {
					t.Fatalf("%s: %v", tt.condition, err)
				}
				matched := d.Matched || len(d.Logged) == 1
				if matched != c.want {
					t.Errorf("%s %s over %+v: matched = %v, want %v", tt.condition, action, c.vars, matched, c.want)
				}
			}
		}
	}
	// A list field takes no comparison, a count no text.
	for _, bad := range []string{
		`{"field":"input.pii.kinds","operator":"=","value":"email"}`,
		`{"field":"input.pii.count","operator":"contains","value":"1"}`,
		`{"field":"input.pii.count","operator":">","value":0.5}`,
	} {
		if _, err := JSONASTToCEL(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// The new fields do not bring pii.entities back: it stays refused for new
// rules, and a stored rule that names it keeps reading [] whatever the
// request carries, so it matches exactly as before.
func TestInputPIIDoesNotReviveRemovedField(t *testing.T) {
	e := newEngine(t)
	raw := `[{"name":"old","action":"block","condition":{"field":"pii.entities","operator":"contains","value":"email"}}]`
	if _, err := e.ValidateRules(json.RawMessage(raw)); !errors.Is(err, ErrRemovedField) {
		t.Errorf("pii.entities in a new rule: err = %v", err)
	}
	vars := &Vars{InputPIIKinds: []string{"email", "phone", "card", "cccd", "ipv4"}, InputPIICount: 5}
	for _, tt := range []struct {
		condition string
		want      bool
	}{
		{`{"field":"pii.entities","operator":"contains","value":"email"}`, false},
		{`{"field":"pii.entities","operator":"contains","value":"EMAIL"}`, false},
		{`{"field":"pii.entities","operator":"in","value":"phone"}`, false},
		{`{"combinator":"and","not":true,"rules":[{"field":"pii.entities","operator":"contains","value":"email"}]}`, true},
	} {
		p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
			ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(tt.condition)}}}
		for _, v := range []*Vars{{}, vars} {
			d, err := e.Evaluate(context.Background(), p, v)
			if err != nil {
				t.Fatalf("%s: %v", tt.condition, err)
			}
			if d.Matched != tt.want {
				t.Errorf("%s over %+v: matched = %v, want %v as before", tt.condition, v, d.Matched, tt.want)
			}
		}
	}
	if act := vars.toActivation(); len(act["pii.entities"].([]string)) != 0 {
		t.Errorf("pii.entities = %v, want []", act["pii.entities"])
	}
}

// Nil kinds read as an empty list, so "x" in input.pii.kinds evaluates.
func TestInputPIIKindsNil(t *testing.T) {
	act := (&Vars{}).toActivation()
	if kinds, ok := act["input.pii.kinds"].([]string); !ok || kinds == nil || len(kinds) != 0 {
		t.Errorf("input.pii.kinds = %#v", act["input.pii.kinds"])
	}
	if act["input.pii.count"] != int64(0) {
		t.Errorf("input.pii.count = %#v", act["input.pii.count"])
	}
}

func TestInputPIISchema(t *testing.T) {
	s := RuleSchema()
	var kinds, count *SchemaField
	for i := range s.Fields {
		switch s.Fields[i].Name {
		case "input.pii.kinds":
			kinds = &s.Fields[i]
		case "input.pii.count":
			count = &s.Fields[i]
		case "pii.entities":
			t.Error("the schema offers the removed pii.entities")
		}
	}
	if kinds == nil || kinds.Type != "list" || !slices.Equal(kinds.Values, outputguard.PIIKinds) {
		t.Errorf("input.pii.kinds = %+v", kinds)
	}
	if count == nil || count.Type != "int" {
		t.Errorf("input.pii.count = %+v", count)
	}
}

// The simulator takes the kinds as a list of strings and the count as a
// whole number.
func TestVarsFromMapInputPII(t *testing.T) {
	v, err := VarsFromMap(map[string]any{"input.pii.kinds": []any{"email", "cccd"}, "input.pii.count": 2.0})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.InputPIIKinds, []string{"email", "cccd"}) || v.InputPIICount != 2 {
		t.Errorf("vars = %+v", v)
	}
	for _, bad := range []map[string]any{
		{"input.pii.kinds": "email"},
		{"input.pii.kinds": []any{"email", 1.0}},
		{"input.pii.count": 1.5},
		{"input.pii.count": -1.0},
		{"pii.entities": []any{"email"}},
	} {
		if _, err := VarsFromMap(bad); err == nil {
			t.Errorf("VarsFromMap(%v) accepted", bad)
		}
	}
}

// Condition text with the list field parses and formats back, also at the
// end of a parenthesized group.
func TestInputPIIConditionText(t *testing.T) {
	text := `!((injection.score > 0.5 && "email" in input.pii.kinds)) || input.pii.count >= 5`
	parsed := mustParse(t, text)
	want := `{"combinator":"or","rules":[{"combinator":"and","not":true,"rules":[{"combinator":"and","rules":[` +
		`{"field":"injection.score","operator":">","value":0.5},` +
		`{"field":"input.pii.kinds","operator":"contains","value":"email"}]}]},` +
		`{"field":"input.pii.count","operator":">=","value":5}]}`
	if string(parsed) != want {
		t.Errorf("parsed\n got %s\nwant %s", parsed, want)
	}
	if again := mustFormat(t, parsed); again != text {
		t.Errorf("format = %q", again)
	}
	expr, err := JSONASTToCEL(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := newEngine(t).ValidateCEL(expr); err != nil {
		t.Errorf("%s: %v", expr, err)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
