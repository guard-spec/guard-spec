// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestDecidedBy(t *testing.T) {
	rule := uuid.New()
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		action string
		rule   *uuid.UUID
		label  *string
		tags   []string
		want   string
	}{
		{"allow", nil, str("jailbreak"), nil, "none"},
		{"log", &rule, nil, nil, "none"},
		{"block", &rule, str("jailbreak"), nil, "rule"},
		{"block", nil, str("jailbreak"), []string{"detector:l1=0.9"}, "detector"},
		{"block", nil, str("UNSCANNED_CONTENT"), nil, "input"},
		{"block", nil, nil, []string{"input:unscanned_image=1"}, "input"},
		{"block", nil, nil, []string{"input:refused=text_only"}, "input"},
		// A detection in a request that also had unscanned parts.
		{"block", nil, str("jailbreak"), []string{"input:unscanned_image=1"}, "detector"},
		{"block", nil, nil, nil, "detector"},
	} {
		if got := decidedBy(c.action, c.rule, c.label, c.tags); got != c.want {
			t.Errorf("%s %v %v %v: %s, want %s", c.action, c.rule != nil, c.label, c.tags, got, c.want)
		}
	}
}
