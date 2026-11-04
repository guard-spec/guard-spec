package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestRouteRules(t *testing.T) {
	e := newEngine(t)
	cond := `{"field":"injection.score","operator":">","value":0.5}`
	rules, err := e.ValidateRules(json.RawMessage(
		`[{"name":"r","action":"route","route_target":"safe-model","condition":` + cond + `}]`))
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].RouteTarget != "safe-model" {
		t.Fatalf("target lost: %+v", rules[0])
	}

	// First match of allow, block or route wins; log goes on.
	logID, routeID := uuid.New(), uuid.New()
	p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{
		{ID: logID, Action: ActionLog, Condition: json.RawMessage(cond)},
		{ID: routeID, Name: "to safe", Action: ActionRoute, RouteTarget: "safe-model", Condition: json.RawMessage(cond)},
		{ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(cond)},
	}}
	d, err := e.Evaluate(context.Background(), p, &Vars{InjectionScore: 0.9})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matched || d.Action != ActionRoute || d.RuleID != routeID || d.RouteTarget != "safe-model" ||
		len(d.Logged) != 1 || d.Logged[0] != logID {
		t.Errorf("decision = %+v", d)
	}
	d, err = e.Evaluate(context.Background(), p, &Vars{InjectionScore: 0.1})
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched || d.Action != ActionAllow || d.RouteTarget != "" {
		t.Errorf("no match: decision = %+v", d)
	}

	if errs := e.CheckRules([]Rule{{Name: "x", Action: ActionRoute, Condition: json.RawMessage(cond)}}); len(errs) != 1 {
		t.Errorf("CheckRules of a route rule without target: %v", errs)
	}
}

func TestSchemaMatchesLeafToCEL(t *testing.T) {
	s := RuleSchema()
	if len(s.Fields) != len(fieldTypes) {
		t.Fatalf("fields = %d, want %d", len(s.Fields), len(fieldTypes))
	}
	e := newEngine(t)
	values := map[string]any{"double": 0.5, "int": 3.0, "string": "a", "bool": true}
	for _, f := range s.Fields {
		if f.Description == "" {
			t.Errorf("%s has no description", f.Name)
		}
		for _, op := range s.Operators[f.Type] {
			v := values[f.Type]
			if op == "in" {
				v = []any{"a"}
			}
			raw, _ := json.Marshal(map[string]any{"field": f.Name, "operator": op, "value": v})
			expr, err := JSONASTToCEL(raw)
			if err != nil {
				t.Errorf("schema offers %s %s, leafToCEL refuses: %v", f.Name, op, err)
				continue
			}
			if err := e.ValidateCEL(expr); err != nil {
				t.Errorf("%s %s does not compile: %v", f.Name, op, err)
			}
		}
	}
	// Operators the schema does not list are refused for that type.
	for _, tt := range []struct{ field, op string }{
		{"scores.l2", "contains"}, {"request.model", ">"}, {"anomaly.has_bidi", "<"}, {"scores.l2", "beginsWith"},
	} {
		raw, _ := json.Marshal(map[string]any{"field": tt.field, "operator": tt.op, "value": "a"})
		if _, err := JSONASTToCEL(raw); err == nil {
			t.Errorf("%s %s accepted", tt.field, tt.op)
		}
	}
	want := []Action{ActionAllow, ActionBlock, ActionLog, ActionRoute}
	if len(s.Actions) != len(want) {
		t.Fatalf("actions = %v", s.Actions)
	}
}

func TestSimulate(t *testing.T) {
	e := newEngine(t)
	cond := func(field, op string, v any) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"field": field, "operator": op, "value": v})
		return raw
	}
	p1, p2 := uuid.New(), uuid.New()
	logRule := Rule{ID: uuid.New(), Name: "log", Action: ActionLog, Condition: cond("scores.l2", ">", 0.5)}
	miss := Rule{ID: uuid.New(), Name: "miss", Action: ActionBlock, Condition: cond("request.model", "=", "other")}
	route := Rule{ID: uuid.New(), Name: "route", Action: ActionRoute, RouteTarget: "safe-model",
		Condition: cond("injection.category", "=", "jailbreak")}
	after := Rule{ID: uuid.New(), Name: "after", Action: ActionBlock, Condition: cond("scores.l2", ">", 0.5)}
	vars, err := VarsFromMap(map[string]any{"request.model": "gpt-4o", "scores.l2": 0.91,
		"injection.category": "jailbreak", "request.tokens": 12.0, "anomaly.has_bidi": false})
	if err != nil {
		t.Fatal(err)
	}
	trace, d, failed := e.Simulate(context.Background(), []SimPolicy{
		{ID: &p1, Rules: []Rule{logRule, miss}},
		{ID: &p2, Rules: []Rule{route, after}},
	}, vars)
	if failed != nil {
		t.Fatal(failed)
	}
	if d.Action != ActionRoute || d.RuleID != route.ID || d.RouteTarget != "safe-model" || len(d.Logged) != 1 {
		t.Errorf("decision = %+v", d)
	}
	wantMatched := []bool{true, false, true, true}
	if len(trace) != 4 {
		t.Fatalf("trace = %+v", trace)
	}
	for i, m := range wantMatched {
		if trace[i].Matched != m || trace[i].Error != "" {
			t.Errorf("trace[%d] = %+v, want matched %v", i, trace[i], m)
		}
	}
	if *trace[0].PolicyID != p1 || *trace[2].PolicyID != p2 || trace[2].RuleName != "route" {
		t.Errorf("trace ids: %+v", trace)
	}

	// A rule that does not compile fails the simulation, as it fails the gateway.
	broken := Rule{ID: uuid.New(), Name: "broken", Action: ActionBlock, Condition: json.RawMessage(`{}`)}
	trace, _, failed = e.Simulate(context.Background(), []SimPolicy{{Rules: []Rule{route, broken}}}, vars)
	if failed == nil || trace[1].Error == "" || trace[0].PolicyID != nil {
		t.Errorf("broken rule: failed=%v trace=%+v", failed, trace)
	}

	// No match: allow.
	_, d, failed = e.Simulate(context.Background(), []SimPolicy{{Rules: []Rule{miss}}}, &Vars{})
	if failed != nil || d.Matched || d.Action != ActionAllow {
		t.Errorf("no match: %+v %v", d, failed)
	}
}

func TestVarsFromMap(t *testing.T) {
	all := map[string]any{}
	for name, typ := range fieldTypes {
		switch typeName(typ) {
		case "double", "int":
			all[name] = 1.0
		case "string":
			all[name] = "x"
		case "bool":
			all[name] = true
		}
	}
	v, err := VarsFromMap(all)
	if err != nil {
		t.Fatal(err)
	}
	act := v.toActivation()
	for name := range fieldTypes {
		switch x := act[name].(type) {
		case float64:
			if x != 1 {
				t.Errorf("%s = %v", name, x)
			}
		case int64:
			if x != 1 {
				t.Errorf("%s = %v", name, x)
			}
		case string:
			if x != "x" {
				t.Errorf("%s = %q", name, x)
			}
		case bool:
			if !x {
				t.Errorf("%s = false", name)
			}
		}
	}
	for _, bad := range []map[string]any{
		{"nope": 1.0}, {"toxicity.score": 1.0}, {"scores.l2": "high"}, {"request.tokens": 1.5},
		{"request.model": 1.0}, {"anomaly.has_bidi": "true"},
	} {
		if _, err := VarsFromMap(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
