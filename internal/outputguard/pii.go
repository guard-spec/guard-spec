// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

// PIIKinds are the kinds CountPII reports, in the order the schema lists
// them: the personal-data detectors of the output guard. They are regular
// expressions with boundary checks, not named-entity recognition: names,
// street addresses and bank account numbers are not found.
var PIIKinds = []string{KindEmail, KindPhone, KindCard, KindCCCD, KindIPv4}

// piiScanner runs every personal-data detector, IPv4 included, and no canary.
var piiScanner = New(Config{RedactPII: true, RedactIPv4: true}).ForRequest("")

// CountPII counts the personal data in text by kind (PIIKinds), with the
// detectors and the overlap rule the output guard redacts with
// (inlineMatches): a stretch of text counts once, as the first detector that
// claims it. It returns nil when there is none. The values found are never
// kept or returned. The gateway runs it on request text (input.pii.*).
func CountPII(text string) Counts {
	var counts Counts
	for _, m := range piiScanner.inlineMatches(text, 0) {
		if counts == nil {
			counts = Counts{}
		}
		counts[m.kind]++
	}
	return counts
}
