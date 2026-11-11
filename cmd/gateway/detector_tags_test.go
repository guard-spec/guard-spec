// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

func TestDetectorTags(t *testing.T) {
	if got := detectorTags(nil); got != nil {
		t.Errorf("no detail: %v", got)
	}
	long := strings.Repeat("x", 80)
	d := &inference.Detail{L1: 0.91234, L2: fusion.Missing, L3: 0.02,
		Rules: []string{"override_ignore_previous", "", "override_ignore_previous", "l3:jailbreak", long}}
	want := []string{"detector:l1=0.912", "detector:l3=0.020", "detector:rule=override_ignore_previous",
		"detector:rule=l3:jailbreak", "detector:rule=" + long[:maxDetectorRuleLen]}
	if got := detectorTags(d); !slices.Equal(got, want) {
		t.Errorf("tags\n got %v\nwant %v", got, want)
	}
	many := &inference.Detail{L1: 0, L2: 1, L3: fusion.Missing}
	for i := range 20 {
		many.Rules = append(many.Rules, "r"+strings.Repeat("a", i+1))
	}
	got := detectorTags(many)
	if len(got) != 2+maxDetectorRules || got[0] != "detector:l1=0.000" || got[1] != "detector:l2=1.000" {
		t.Errorf("bounded: %v", got)
	}
}

// inputAuditTags is the audit row's tags without the detector's, for the
// tests of the other tags.
func inputAuditTags(e requestEntry) []string {
	return withoutDetector(auditTags(e))
}

// withoutDetector leaves out the detector's tags (nil when nothing else is
// left, as the column of a row without tags).
func withoutDetector(tags []string) []string {
	out := slices.DeleteFunc(slices.Clone(tags), func(s string) bool { return strings.HasPrefix(s, "detector:") })
	if len(out) == 0 {
		return nil
	}
	return out
}

// The audit row ends with the detector's tags, after the input tags.
func TestAuditTagsDetector(t *testing.T) {
	e := requestEntry{Redacted: 1}
	e.Scores.Injection.Detail = &inference.Detail{L1: 0.5, L2: fusion.Missing, L3: fusion.Missing, Rules: []string{"r1"}}
	got := auditTags(e)
	if !slices.Equal(got, []string{"input:redacted=1", "detector:l1=0.500", "detector:rule=r1"}) {
		t.Errorf("tags %v", got)
	}
}
