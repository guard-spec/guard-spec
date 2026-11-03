package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLogRuleDoesNotStopTheChain(t *testing.T) {
	e := newEngine(t)
	always := json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)
	logA, logB, block := uuid.New(), uuid.New(), uuid.New()
	first := Policy{ID: uuid.New(), Version: 1, Rules: []Rule{
		{ID: logA, Action: ActionLog, Condition: always},
	}}
	second := Policy{ID: uuid.New(), Version: 1, Rules: []Rule{
		{ID: logB, Action: ActionLog, Condition: always},
		{ID: block, Action: ActionBlock, Condition: always},
	}}
	decision, err := e.EvaluateAll(context.Background(), []Policy{first, second}, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != ActionBlock || decision.RuleID != block {
		t.Errorf("decision = %+v, want the block rule after the log rules", decision)
	}
	if len(decision.Logged) != 2 || decision.Logged[0] != logA || decision.Logged[1] != logB {
		t.Errorf("logged = %v", decision.Logged)
	}

	// Only log rules match: allow by default, with the matches recorded.
	decision, err = e.EvaluateAll(context.Background(), []Policy{first}, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Matched || decision.Action != ActionAllow || len(decision.Logged) != 1 {
		t.Errorf("decision = %+v", decision)
	}
}

func TestRemovedFieldsRefusedForNewRules(t *testing.T) {
	e := newEngine(t)
	for _, field := range []string{"toxicity.score", "pii.entities", "topic.categories"} {
		op, value := "contains", `"x"`
		if field == "toxicity.score" {
			op, value = ">", "0.5"
		}
		raw := `[{"name":"old","action":"block","condition":{"field":"` + field +
			`","operator":"` + op + `","value":` + value + `}}]`
		_, err := e.ValidateRules(json.RawMessage(raw))
		if !errors.Is(err, ErrRemovedField) || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: err = %v", field, err)
		}
	}
	if err := e.ValidateCEL("toxicity.score > 0.5"); !errors.Is(err, ErrRemovedField) {
		t.Errorf("raw CEL: err = %v", err)
	}
}

// A stored rule naming a removed field keeps working as before (the field was
// always zero), so the upgrade does not turn it into a fail-closed 503.
func TestStoredRuleWithRemovedFieldStillEvaluates(t *testing.T) {
	e := newEngine(t)
	tests := []struct {
		condition string
		want      bool
	}{
		{`{"field":"toxicity.score","operator":">","value":0.5}`, false},
		{`{"field":"toxicity.score","operator":"<","value":0.5}`, true},
		{`{"field":"pii.entities","operator":"contains","value":"EMAIL"}`, false},
		{`{"field":"topic.categories","operator":"in","value":"x"}`, false},
	}
	for _, tt := range tests {
		p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
			ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(tt.condition)}}}
		d, err := e.Evaluate(context.Background(), p, &Vars{})
		if err != nil {
			t.Fatalf("%s: %v", tt.condition, err)
		}
		if d.Matched != tt.want {
			t.Errorf("%s: matched = %v", tt.condition, d.Matched)
		}
		if errs := e.CheckRules(p.Rules); len(errs) != 1 || !errors.Is(errs[0], ErrRemovedField) {
			t.Errorf("%s: check = %v", tt.condition, errs)
		}
	}
}

func TestCheckRules(t *testing.T) {
	e := newEngine(t)
	good := json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)
	rules := []Rule{
		{ID: uuid.New(), Name: "ok", Action: ActionBlock, Condition: good},
		{ID: uuid.New(), Name: "stale action", Action: ActionRedact, Condition: good},
		{ID: uuid.New(), Name: "broken", Action: ActionLog, Condition: json.RawMessage(`{}`)},
	}
	errs := e.CheckRules(rules)
	if len(errs) != 2 {
		t.Fatalf("errs = %v", errs)
	}
	if !strings.Contains(errs[0].Error(), "stale action") || !strings.Contains(errs[1].Error(), "broken") {
		t.Errorf("errs = %v", errs)
	}
}
