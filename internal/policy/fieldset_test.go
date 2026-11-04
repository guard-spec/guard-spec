// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
)

func TestConditionOverFieldSet(t *testing.T) {
	fs := FieldSet{"type": String, "severity": String, "attrs.score": Double, "attrs.categories": StringList,
		"attrs.status": Int}
	cases := []struct {
		text string
		vars map[string]any
		want bool
	}{
		{`type == "detection.blocked" && attrs.score >= 0.9`, nil, true},
		{`"jailbreak" in attrs.categories`, nil, true},
		{`attrs.status >= 500`, nil, false},
		{`severity in ["warning", "critical"]`, nil, false},
	}
	base := map[string]any{"type": "detection.blocked", "severity": "info", "attrs.score": 0.95,
		"attrs.categories": []string{"jailbreak"}, "attrs.status": int64(0)}
	for _, tc := range cases {
		expr, err := ParseConditionIn(tc.text, fs)
		if err != nil {
			t.Fatalf("%s: %v", tc.text, err)
		}
		c, err := CompileCondition(expr, fs)
		if err != nil {
			t.Fatalf("%s: compile %q: %v", tc.text, expr, err)
		}
		got, err := c.Match(context.Background(), base)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %v, %v; want %v", tc.text, got, err, tc.want)
		}
	}
	// Policy fields are not part of the set, and the other way around.
	if _, err := ParseConditionIn(`injection.score > 0.5`, fs); err == nil {
		t.Fatal("a policy field was accepted")
	}
	if _, err := ParseCondition(`attrs.score > 0.5`); err == nil {
		t.Fatal("an alert field was accepted by the policy parser")
	}
	var pe *ParseError
	if _, err := ParseConditionIn(`attrs.score >`, fs); err == nil {
		t.Fatal("syntax error accepted")
	} else if p, ok := AsParseError(err); !ok || p.Message == "" {
		t.Fatalf("not a parse error: %v %v", err, pe)
	}
	if c, err := CompileCondition("", fs); err != nil {
		t.Fatal(err)
	} else if ok, _ := c.Match(context.Background(), nil); !ok {
		t.Fatal("empty condition must match")
	}
}
