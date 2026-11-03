package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// TestIndirectFields covers indirect.score, indirect.source and
// injection.source_role.
func TestIndirectFields(t *testing.T) {
	vars := &Vars{InjectionScore: 0.9, IndirectScore: 0.9, IndirectSource: "tool_description", SourceRole: "tool_description"}
	none := &Vars{InjectionScore: 0.1, SourceRole: "user"}
	tests := []struct {
		condition string
		v         *Vars
		want      bool
	}{
		{`{"field":"indirect.score","operator":">=","value":0.85}`, vars, true},
		{`{"field":"indirect.score","operator":">","value":0}`, none, false},
		{`{"field":"indirect.source","operator":"=","value":"tool_description"}`, vars, true},
		{`{"field":"indirect.source","operator":"in","value":"tool, document"}`, vars, false},
		{`{"field":"indirect.source","operator":"=","value":""}`, none, true},
		{`{"field":"injection.source_role","operator":"=","value":"user"}`, none, true},
		{`{"field":"injection.source_role","operator":"!=","value":"user"}`, vars, true},
	}
	e := newEngine(t)
	for _, tt := range tests {
		p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
			ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(tt.condition)}}}
		d, err := e.Evaluate(context.Background(), p, tt.v)
		if err != nil {
			t.Fatalf("%s: %v", tt.condition, err)
		}
		if d.Matched != tt.want {
			t.Errorf("%s: matched = %v, want %v", tt.condition, d.Matched, tt.want)
		}
	}
}
