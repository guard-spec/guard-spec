package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func group(rules string) string {
	return `{"combinator":"and","rules":[` + rules + `]}`
}

func TestConditionsThatCompileAlsoEvaluate(t *testing.T) {
	vars := &Vars{
		RequestModel:   "gpt-4o",
		RequestTokens:  2000000,
		InjectionScore: 0.75,
	}
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"double field, fractional value", `{"field":"injection.score","operator":">=","value":0.7}`, true},
		{"double field, whole value", `{"field":"injection.score","operator":">=","value":1}`, false},
		{"double field, value as string", `{"field":"injection.score","operator":">=","value":"0.7"}`, true},
		{"int field, large value", `{"field":"request.tokens","operator":">=","value":1000000}`, true},
		{"int field, value as string", `{"field":"request.tokens","operator":"<","value":"5"}`, false},
		{"string equals", `{"field":"request.model","operator":"=","value":"gpt-4o"}`, true},
		{"string contains", `{"field":"request.model","operator":"contains","value":"gpt"}`, true},
		{"string in list", `{"field":"request.model","operator":"in","value":["a","gpt-4o"]}`, true},
		{"string in comma list", `{"field":"request.model","operator":"in","value":"a, gpt-4o"}`, true},
		{"bool", `{"field":"anomaly.has_bidi","operator":"=","value":false}`, true},
		{"bool as string", `{"field":"anomaly.has_bidi","operator":"!=","value":"true"}`, true},
		{"quote cannot escape the literal", `{"field":"request.model","operator":"=","value":"x\" || true || \"y"}`, false},
		{"or group", `{"combinator":"OR","rules":[{"field":"request.tokens","operator":"<","value":1},{"field":"injection.score","operator":">","value":0.5}]}`, true},
		{"negated group", `{"combinator":"and","not":true,"rules":[{"field":"injection.score","operator":">","value":0.5}]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEngine(t)
			p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
				ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(tt.condition)}}}
			decision, err := e.Evaluate(context.Background(), p, vars)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Matched != tt.want {
				t.Errorf("matched = %v, want %v", decision.Matched, tt.want)
			}
		})
	}
}

func TestConditionsRefused(t *testing.T) {
	tests := []struct {
		name      string
		condition string
	}{
		{"no condition", ``},
		{"null condition", `null`},
		{"empty leaf would match everything", `{}`},
		{"empty group", `{"combinator":"and","rules":[]}`},
		{"unknown combinator", `{"combinator":"xor","rules":[{"field":"request.model","operator":"=","value":"a"}]}`},
		{"unknown field", `{"field":"no.such","operator":"=","value":"a"}`},
		{"expression as field", `{"field":"true || request.model","operator":"=","value":"a"}`},
		{"unknown operator", `{"field":"request.model","operator":"matches","value":"a"}`},
		{"ordering on a string", `{"field":"request.model","operator":">","value":"a"}`},
		{"string for a number", `{"field":"injection.score","operator":">","value":"high"}`},
		{"NaN", `{"field":"injection.score","operator":">","value":"NaN"}`},
		{"fraction for an int", `{"field":"request.tokens","operator":">","value":1.5}`},
		{"number for a string", `{"field":"request.model","operator":"=","value":5}`},
		{"null value", `{"field":"request.model","operator":"=","value":null}`},
		{"removed toxicity", `{"field":"toxicity.score","operator":">","value":0.5}`},
		{"removed pii", `{"field":"pii.entities","operator":"contains","value":"EMAIL"}`},
		{"removed topic", `{"field":"topic.categories","operator":"contains","value":"x"}`},
		{"in on a number", `{"field":"injection.score","operator":"in","value":"1"}`},
		{"empty in", `{"field":"request.model","operator":"in","value":""}`},
		{"field as value source", `{"field":"request.model","operator":"=","value":"request.tenant_id","valueSource":"field"}`},
		{"disabled rule", `{"field":"request.model","operator":"=","value":"a","disabled":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if expr, err := JSONASTToCEL(json.RawMessage(tt.condition)); err == nil {
				t.Errorf("accepted as %q", expr)
			}
		})
	}
}

func TestValidateRules(t *testing.T) {
	e := newEngine(t)
	cond := group(`{"field":"injection.score","operator":">=","value":0.7}`)

	id := uuid.New()
	raw := `[{"name":"a","action":"block","condition":` + cond + `},
	         {"id":"` + id.String() + `","name":"b","action":"log","condition":` + cond + `}]`
	rules, err := e.ValidateRules(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].ID == uuid.Nil {
		t.Error("missing id not filled in")
	}
	if rules[1].ID != id {
		t.Error("given id not kept")
	}

	refused := map[string]string{
		"redact":       `[{"name":"a","action":"redact","condition":` + cond + `}]`,
		"route":        `[{"name":"a","action":"route","route_target":"x","condition":` + cond + `}]`,
		"unknown":      `[{"name":"a","action":"delete","condition":` + cond + `}]`,
		"no action":    `[{"name":"a","condition":` + cond + `}]`,
		"bad field":    `[{"name":"a","action":"block","condition":{"field":"x","operator":"=","value":"a"}}]`,
		"null":         `null`,
		"not a list":   `{}`,
		"duplicate id": `[{"id":"` + id.String() + `","action":"log","condition":` + cond + `},{"id":"` + id.String() + `","action":"log","condition":` + cond + `}]`,
	}
	for name, raw := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := e.ValidateRules(json.RawMessage(raw)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestFirstMatchWins(t *testing.T) {
	e := newEngine(t)
	cond := json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)
	first, second := uuid.New(), uuid.New()
	p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{
		{ID: first, Action: ActionAllow, Condition: cond},
		{ID: second, Action: ActionBlock, Condition: cond},
	}}
	decision, err := e.Evaluate(context.Background(), p, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RuleID != first || decision.Action != ActionAllow {
		t.Errorf("decision = %+v", decision)
	}
}

func TestEvaluateErrorsInsteadOfAllowing(t *testing.T) {
	e, err := NewWithCostLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
		ID: uuid.New(), Action: ActionBlock,
		Condition: json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)}}}
	decision, err := e.Evaluate(context.Background(), p, &Vars{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if decision.Action != "" {
		t.Errorf("decision = %+v, want empty", decision)
	}
}

func TestCostLimitStopsExpensiveExpression(t *testing.T) {
	e := newEngine(t)
	// Far beyond any budget: 1000^4 iterations would run for days.
	items := "[" + strings.TrimSuffix(strings.Repeat("1,", 1000), ",") + "]"
	expr := items + ".all(a, " + items + ".all(b, " + items + ".all(c, " + items + ".all(d, a + b + c + d == 4))))"
	prg, err := e.compileExpr(expr)
	if err != nil {
		t.Fatal(err)
	}
	cp := &compiledPolicy{rules: []compiledRule{{id: uuid.New(), action: ActionAllow, program: prg}}}

	done := make(chan error, 1)
	go func() {
		var spent uint64
		_, err := cp.evaluate(context.Background(), &Vars{}, e.costBudget, &spent)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a cost error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("evaluation did not stop")
	}
}

func TestCostLimitLeavesLargeRuleWorking(t *testing.T) {
	e := newEngine(t)
	leaf := `{"field":"request.model","operator":"contains","value":"x"}`
	cond := `{"combinator":"or","rules":[` + strings.TrimSuffix(strings.Repeat(leaf+",", 200), ",") + `]}`
	p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
		ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(cond)}}}
	if _, err := e.Evaluate(context.Background(), p, &Vars{RequestModel: strings.Repeat("y", 100)}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionBumpRecompiles(t *testing.T) {
	e := newEngine(t)
	id := uuid.New()
	eval := func(version int, action Action) Decision {
		t.Helper()
		d, err := e.Evaluate(context.Background(), &Policy{ID: id, Version: version, Rules: []Rule{{
			ID: uuid.New(), Action: action,
			Condition: json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)}}}, &Vars{})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := eval(1, ActionAllow); d.Action != ActionAllow {
		t.Fatalf("v1 = %+v", d)
	}
	if d := eval(2, ActionBlock); d.Action != ActionBlock {
		t.Errorf("v2 = %+v", d)
	}
}

// cheapRules returns n rules that never match, so evaluation runs all of them.
func cheapRules(n int) []Rule {
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = Rule{ID: uuid.New(), Action: ActionBlock,
			Condition: json.RawMessage(`{"field":"request.tokens","operator":"<","value":0}`)}
	}
	return rules
}

func TestExpiredContextStopsBetweenRules(t *testing.T) {
	e := newEngine(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	p := &Policy{ID: uuid.New(), Version: 1, Rules: cheapRules(3)}
	decision, err := e.Evaluate(ctx, p, &Vars{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if decision.Action != "" {
		t.Errorf("decision = %+v, want empty", decision)
	}
}

func TestCostBudgetSpansRulesAndPolicies(t *testing.T) {
	e := newEngine(t)
	one := []Policy{{ID: uuid.New(), Version: 1, Rules: cheapRules(1)}}
	var spent uint64
	cp, err := e.getOrCompile(&one[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.evaluate(context.Background(), &Vars{}, e.costBudget, &spent); err != nil || spent == 0 {
		t.Fatalf("spent = %d, err = %v", spent, err)
	}
	// Room for exactly four rules: five fail whether in one policy or split.
	e.costBudget = 4 * spent

	if _, err := e.EvaluateAll(context.Background(), []Policy{
		{ID: uuid.New(), Version: 1, Rules: cheapRules(4)}}, &Vars{}); err != nil {
		t.Fatalf("four rules: %v", err)
	}
	if _, err := e.EvaluateAll(context.Background(), []Policy{
		{ID: uuid.New(), Version: 1, Rules: cheapRules(5)}}, &Vars{}); !errors.Is(err, ErrCostBudget) {
		t.Errorf("five rules in one policy: err = %v", err)
	}
	decision, err := e.EvaluateAll(context.Background(), []Policy{
		{ID: uuid.New(), Version: 1, Rules: cheapRules(3)},
		{ID: uuid.New(), Version: 1, Rules: cheapRules(2)}}, &Vars{})
	if !errors.Is(err, ErrCostBudget) || decision.Action != "" {
		t.Errorf("five rules across policies: %+v, err = %v", decision, err)
	}
}

func TestValidateRulesCapsRuleCount(t *testing.T) {
	e := newEngine(t)
	for _, n := range []int{MaxRules, MaxRules + 1} {
		raw, err := json.Marshal(cheapRules(n))
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.ValidateRules(raw)
		if ok := err == nil; ok != (n <= MaxRules) {
			t.Errorf("%d rules: err = %v", n, err)
		}
		if n > MaxRules && err != nil && !strings.Contains(err.Error(), fmt.Sprint(MaxRules)) {
			t.Errorf("error does not name the limit: %v", err)
		}
	}
}

func TestOlderVersionsAreEvicted(t *testing.T) {
	e := newEngine(t)
	id := uuid.New()
	for v := 1; v <= 5; v++ {
		if _, err := e.Evaluate(context.Background(), &Policy{ID: id, Version: v, Rules: cheapRules(1)}, &Vars{}); err != nil {
			t.Fatal(err)
		}
	}
	// A late request still holding an old version must not displace the newest.
	if _, err := e.Evaluate(context.Background(), &Policy{ID: id, Version: 2, Rules: cheapRules(1)}, &Vars{}); err != nil {
		t.Fatal(err)
	}
	if len(e.cache) != 1 || e.cache[id].version != 5 {
		t.Errorf("cache holds %d entries, version %d", len(e.cache), e.cache[id].version)
	}
}
