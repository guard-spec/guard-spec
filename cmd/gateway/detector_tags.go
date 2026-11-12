// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"

	"github.com/guard-spec/guard-spec/internal/inference"
)

// The detector's explanation in the request log (RF-a1dbafea U2): the
// calibrated score of each layer that ran and the ids of the rules and
// categories that fired, so that the admin UI can show why a request was
// refused without storing its text:
//
//	detector:l1=0.912   detector:l2=0.351   detector:l3=0.020
//	detector:rule=override_ignore_previous   detector:rule=l2:jailbreak
//
// A layer that did not run (light mode, the cascade) has no tag. Rule ids
// name built-in rules and categories, never request text.

// maxDetectorRules bounds the rule tags of one row.
const maxDetectorRules = 8

// maxDetectorRuleLen bounds one rule id.
const maxDetectorRuleLen = 64

// detectorTags renders the fused score's detail; nil without one (a request
// refused before the scan).
func detectorTags(d *inference.Detail) []string {
	if d == nil {
		return nil
	}
	var tags []string
	for i, v := range [3]float64{d.L1, d.L2, d.L3} {
		if v < 0 {
			continue // the layer did not run
		}
		tags = append(tags, "detector:l"+strconv.Itoa(i+1)+"="+strconv.FormatFloat(v, 'f', 3, 64))
	}
	seen := map[string]bool{}
	for _, r := range d.Rules {
		if len(seen) == maxDetectorRules {
			break
		}
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		if len(r) > maxDetectorRuleLen {
			r = r[:maxDetectorRuleLen]
		}
		tags = append(tags, "detector:rule="+r)
	}
	return tags
}
