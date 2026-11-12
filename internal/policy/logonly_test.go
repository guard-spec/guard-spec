// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// A log-only policy records what it would have decided and never decides:
// the next policy, or the default allow, does.
func TestLogOnlyPolicyRecordsWithoutDeciding(t *testing.T) {
	e := newEngine(t)
	always := json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)
	never := json.RawMessage(`{"field":"request.tokens","operator":"<","value":0}`)
	wouldBlock, logged, live := uuid.New(), uuid.New(), uuid.New()
	shadow := Policy{ID: uuid.New(), Version: 1, LogOnly: true, Rules: []Rule{
		{ID: logged, Name: "log", Action: ActionLog, Condition: always},
		{ID: wouldBlock, Name: "would block", Action: ActionBlock, Condition: always},
		{ID: uuid.New(), Name: "after", Action: ActionAllow, Condition: never},
	}}
	ctx := context.Background()

	// Alone: the default allow, with the match recorded.
	d, err := e.Evaluate(ctx, &shadow, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched || d.Action != ActionAllow || d.RuleID != uuid.Nil {
		t.Errorf("log-only policy decided: %+v", d)
	}
	if len(d.LogOnly) != 1 || d.LogOnly[0].RuleID != wouldBlock || d.LogOnly[0].Action != ActionBlock || d.LogOnly[0].RuleName != "would block" {
		t.Errorf("LogOnly = %+v, want the would-block rule", d.LogOnly)
	}
	if !d.WouldBlock() {
		t.Error("WouldBlock() = false")
	}
	if len(d.Logged) != 1 || d.Logged[0] != logged {
		t.Errorf("Logged = %v, want the log rule", d.Logged)
	}

	// Before a live policy: the live one decides, and the shadow match is kept.
	livePolicy := Policy{ID: uuid.New(), Version: 1, Rules: []Rule{{ID: live, Name: "live", Action: ActionBlock, Condition: always}}}
	d, err = e.EvaluateAll(ctx, []Policy{shadow, livePolicy}, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matched || d.RuleID != live || d.Action != ActionBlock {
		t.Errorf("live policy did not decide: %+v", d)
	}
	if len(d.LogOnly) != 1 || d.LogOnly[0].RuleID != wouldBlock {
		t.Errorf("LogOnly = %+v", d.LogOnly)
	}

	// The same policy live blocks: log-only is the only difference.
	shadow.LogOnly = false
	shadow.Version = 2
	d, err = e.Evaluate(ctx, &shadow, &Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matched || d.RuleID != wouldBlock || len(d.LogOnly) != 0 {
		t.Errorf("live decision = %+v", d)
	}
}

func TestSimulateLogOnly(t *testing.T) {
	e := newEngine(t)
	always := json.RawMessage(`{"field":"request.tokens","operator":">=","value":0}`)
	shadowID, liveID := uuid.New(), uuid.New()
	block, allow := uuid.New(), uuid.New()
	trace, decision, failed := e.Simulate(context.Background(), []SimPolicy{
		{ID: &shadowID, LogOnly: true, Rules: []Rule{{ID: block, Name: "shadow block", Action: ActionBlock, Condition: always}}},
		{ID: &liveID, Rules: []Rule{{ID: allow, Name: "allow", Action: ActionAllow, Condition: always}}},
	}, &Vars{})
	if failed != nil {
		t.Fatal(failed)
	}
	if decision.RuleID != allow || decision.Action != ActionAllow {
		t.Errorf("decision = %+v", decision)
	}
	if len(decision.LogOnly) != 1 || decision.LogOnly[0].RuleID != block {
		t.Errorf("LogOnly = %+v", decision.LogOnly)
	}
	if len(trace) != 2 || !trace[0].Matched || !trace[0].LogOnly || trace[1].LogOnly {
		t.Errorf("trace = %+v", trace)
	}
}
