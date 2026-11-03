package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// TestLayerScoreFields covers the per-layer fusion fields: scores.l1..l3
// (-1 when a layer did not run) and injection.category.
func TestLayerScoreFields(t *testing.T) {
	vars := &Vars{InjectionScore: 0.9, ScoreL1: 0.9, ScoreL2: -1, ScoreL3: -1, InjectionCat: "jailbreak"}
	tests := []struct {
		condition string
		want      bool
	}{
		{`{"field":"scores.l1","operator":">=","value":0.85}`, true},
		{`{"field":"scores.l2","operator":">=","value":0}`, false},
		{`{"field":"scores.l3","operator":"<","value":0}`, true},
		{`{"field":"injection.category","operator":"=","value":"jailbreak"}`, true},
		{`{"field":"injection.category","operator":"in","value":"prompt_extraction, data_exfiltration"}`, false},
	}
	e := newEngine(t)
	for _, tt := range tests {
		p := &Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{
			ID: uuid.New(), Action: ActionBlock, Condition: json.RawMessage(tt.condition)}}}
		d, err := e.Evaluate(context.Background(), p, vars)
		if err != nil {
			t.Fatalf("%s: %v", tt.condition, err)
		}
		if d.Matched != tt.want {
			t.Errorf("%s: matched = %v, want %v", tt.condition, d.Matched, tt.want)
		}
	}
}
