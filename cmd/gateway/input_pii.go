// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
)

// Personal data in requests (ADR 0003). When an org turns on input_pii in its
// guard settings, the gateway counts the personal data in the request text
// with the output guard's detectors (outputguard.CountPII: e-mail, Vietnamese
// phone, payment card with the Luhn check, CCCD, IPv4) and gives rules
// input.pii.kinds and input.pii.count. Only kinds and counts are kept: they go
// to the rules, the audit row (input:pii_<kind>=<n>) and detection events,
// never the values. Nothing is redacted; the request goes upstream as it is
// unless a rule blocks it.
//
// The text is the cleaned text the injection scan collects (textGuard.collect),
// of three sources:
//
//   - user: user turns, a legacy prompt and suffix, Responses prompt
//     variables;
//   - tool: tool results, the readable text of web search and fetch results,
//     and Responses tool output items;
//   - document: Messages API document and search_result blocks.
//
// System and developer prompts (and Responses instructions) are left out,
// even when SCAN_ROLES scans them for injection: they are the operator's own
// text, which often holds example addresses and numbers, so counting them
// would make every request of an application match. So are the assistant's
// tool-call arguments, which repeat what the model was given, and tool
// descriptions. A source that SCAN_ROLES (or the org) does not scan is not
// checked either: the check reads what the injection scan reads.
//
// Earlier turns count too, also on /v1/messages with SCAN_HISTORY=latest
// where their user text is not classified again: they go upstream with every
// request, and the check costs no model call, so the three APIs give the same
// result for the same conversation.
//
// With the setting off the guard does not call CountPII at all.

// piiCounter is the detector; tests count its calls.
var piiCounter = outputguard.CountPII

// piiSource reports whether text from src is checked for personal data.
func piiSource(src indirect.Source) bool {
	return src == indirect.SourceUser || src == indirect.SourceTool || src == indirect.SourceDocument
}

// countPII adds the personal data in text, cleaned text from src, to g.pii
// when the org has the check on.
func (g *textGuard) countPII(src indirect.Source, text string) {
	if !g.detectPII || !piiSource(src) {
		return
	}
	found := piiCounter(text)
	if len(found) == 0 {
		return
	}
	if g.pii == nil {
		g.pii = outputguard.Counts{}
	}
	for kind, n := range found {
		g.pii[kind] += n
	}
}

// piiVars returns input.pii.kinds, in the order of outputguard.PIIKinds, and
// input.pii.count.
func piiVars(counts outputguard.Counts) ([]string, int) {
	var kinds []string
	for _, kind := range outputguard.PIIKinds {
		if counts[kind] > 0 {
			kinds = append(kinds, kind)
		}
	}
	return kinds, counts.Total()
}

// piiTags renders the counts for the audit row's pii_entities column, as
// "input:pii_<kind>=<n>" in the order of outputguard.PIIKinds.
func piiTags(counts outputguard.Counts) []string {
	var tags []string
	for _, kind := range outputguard.PIIKinds {
		if n := counts[kind]; n > 0 {
			tags = append(tags, fmt.Sprintf("input:pii_%s=%d", kind, n))
		}
	}
	return tags
}
