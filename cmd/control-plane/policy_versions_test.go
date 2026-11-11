// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestDiffVersions(t *testing.T) {
	kept, changed, removed, added, moved := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	rules := func(items ...string) json.RawMessage {
		out := "["
		for i, it := range items {
			if i > 0 {
				out += ","
			}
			out += it
		}
		return json.RawMessage(out + "]")
	}
	r := func(id uuid.UUID, name, action, cond string) string {
		return `{"id":"` + id.String() + `","name":"` + name + `","action":"` + action + `","condition":` + cond + `}`
	}
	c1 := `{"field":"scores.l2","operator":">","value":0.9}`
	c1b := `{"value":0.9,"operator":">","field":"scores.l2"}` // the same tree, other key order
	c2 := `{"field":"scores.l2","operator":">","value":0.5}`
	desc := "before"
	from := policyVersion{Version: 3, Name: "p", Description: &desc, Enabled: true, Rules: rules(
		r(kept, "kept", "block", c1), r(changed, "changed", "block", c1), r(removed, "removed", "log", c1), r(moved, "moved", "allow", c1))}
	project := uuid.New()
	to := policyVersion{Version: 5, Name: "p2", ProjectID: &project, Enabled: false, LogOnly: true, Rules: rules(
		r(moved, "moved", "allow", c1), r(kept, "kept", "block", c1b), r(changed, "changed", "block", c2), r(added, "added", "block", c1))}

	d := diffVersions(from, to)
	if d.From != 3 || d.To != 5 {
		t.Errorf("from/to = %d/%d", d.From, d.To)
	}
	fields := map[string][2]any{}
	for _, f := range d.Fields {
		fields[f.Field] = [2]any{f.From, f.To}
	}
	if len(fields) != 5 || fields["name"] != [2]any{"p", "p2"} || fields["description"] != [2]any{"before", ""} ||
		fields["enabled"] != [2]any{true, false} || fields["log_only"] != [2]any{false, true} {
		t.Errorf("fields = %+v", d.Fields)
	}
	if _, ok := fields["project_id"]; !ok {
		t.Errorf("project_id change missing: %+v", d.Fields)
	}
	ops := map[uuid.UUID]ruleChange{}
	for _, rc := range d.Rules {
		ops[rc.RuleID] = rc
	}
	// Same content (key order only), another position: moved, not changed.
	if rc := ops[kept]; rc.Op != "moved" || rc.From != nil || rc.To != nil || rc.FromIndex != 0 || rc.ToIndex != 1 {
		t.Errorf("kept = %+v", rc)
	}
	if rc := ops[changed]; rc.Op != "changed" || rc.From == nil || rc.To == nil || rc.FromIndex != 1 || rc.ToIndex != 2 {
		t.Errorf("changed = %+v", rc)
	}
	if rc := ops[removed]; rc.Op != "removed" || rc.From == nil || rc.To != nil || rc.ToIndex != -1 {
		t.Errorf("removed = %+v", rc)
	}
	if rc := ops[added]; rc.Op != "added" || rc.From != nil || rc.To == nil || rc.FromIndex != -1 || rc.ToIndex != 3 {
		t.Errorf("added = %+v", rc)
	}
	if rc := ops[moved]; rc.Op != "moved" || rc.FromIndex != 3 || rc.ToIndex != 0 {
		t.Errorf("moved = %+v", rc)
	}
	if len(d.Rules) != 5 {
		t.Errorf("rules = %d changes, want 5", len(d.Rules))
	}

	// Identical versions: nothing.
	same := diffVersions(from, from)
	if len(same.Fields) != 0 || len(same.Rules) != 0 {
		t.Errorf("same = %+v", same)
	}
	// Invalid rule lists count as empty rather than failing.
	bad := diffVersions(policyVersion{Rules: json.RawMessage(`nope`)}, from)
	if len(bad.Rules) != 4 {
		t.Errorf("bad = %+v", bad.Rules)
	}
}

// A rule saved without its id gets a new one: the diff pairs it by content,
// then by name, instead of reporting it removed and added.
func TestDiffVersionsRulesWithNewIDs(t *testing.T) {
	r := func(name, action string, value float64) string {
		v, _ := json.Marshal(value)
		return `{"id":"` + uuid.NewString() + `","name":"` + name + `","action":"` + action +
			`","condition":{"field":"scores.l2","operator":">","value":` + string(v) + `}}`
	}
	from := policyVersion{Version: 1, Rules: json.RawMessage("[" + r("a", "block", 0.9) + "," + r("c", "log", 0.4) + "]")}
	to := policyVersion{Version: 2, Rules: json.RawMessage("[" + r("a", "block", 0.9) + "," + r("c", "log", 0.6) + "," + r("b", "log", 0.5) + "]")}
	d := diffVersions(from, to)
	ops := map[string]string{}
	for _, rc := range d.Rules {
		ops[rc.Name] = rc.Op
	}
	if len(d.Rules) != 2 || ops["c"] != "changed" || ops["b"] != "added" {
		t.Errorf("rules = %+v", d.Rules)
	}
}
