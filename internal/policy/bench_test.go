package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// benchVars are the signals of a typical benign request.
var benchVars = Vars{
	RequestModel: "gpt-4o-mini", RequestTenantID: "00000000-0000-0000-0000-000000000001",
	RequestTokens: 350, InjectionLabel: "BENIGN", InjectionScore: 0.04,
	ScoreL1: 0.02, ScoreL2: 0.05, ScoreL3: 0.03, SourceRole: "user",
}

// benchPolicy has n rules that do not match benchVars, so every rule runs.
func benchPolicy(n int) Policy {
	conds := []string{
		`{"combinator":"and","rules":[{"field":"injection.score","operator":">=","value":0.7},{"field":"request.model","operator":"in","value":["gpt-4o","gpt-4o-mini"]}]}`,
		`{"combinator":"or","rules":[{"field":"anomaly.has_tag_chars","operator":"=","value":true},{"field":"anomaly.score","operator":">","value":0.8}]}`,
		`{"combinator":"and","rules":[{"field":"indirect.score","operator":">=","value":0.6},{"field":"indirect.source","operator":"=","value":"tool"}]}`,
		`{"combinator":"and","rules":[{"field":"injection.category","operator":"=","value":"prompt_extraction"},{"field":"scores.l2","operator":">","value":0.5}]}`,
		`{"field":"request.tokens","operator":">","value":100000}`,
	}
	p := Policy{ID: uuid.New(), Version: 1}
	for i := range n {
		action := ActionBlock
		if i%2 == 1 {
			action = ActionLog
		}
		p.Rules = append(p.Rules, Rule{ID: uuid.New(), Name: fmt.Sprintf("r%d", i), Action: action,
			Condition: json.RawMessage(conds[i%len(conds)])})
	}
	return p
}

// BenchmarkEvaluate is CEL evaluation of compiled (cached) policies, the
// per-request cost in the gateway. `make bench` runs it.
func BenchmarkEvaluate(b *testing.B) {
	e, err := New()
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, n := range []int{1, 10, 50} {
		policies := []Policy{benchPolicy(n)}
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			vars := benchVars
			if _, err := e.EvaluateAll(ctx, policies, &vars); err != nil { // compile once
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				d, err := e.EvaluateAll(ctx, policies, &vars)
				if err != nil || d.Matched {
					b.Fatalf("decision %+v, err %v", d, err)
				}
			}
		})
	}
}
