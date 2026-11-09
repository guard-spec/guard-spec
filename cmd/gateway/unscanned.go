// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/metrics"
)

// Unscanned content (RF-c18516ae). Images, files and audio are forwarded but
// never read by the detectors, so an injection inside them is not
// classified. UNSCANNED_PARTS (and the org's stricter unscanned_parts) says
// what happens: allow forwards them, log forwards them and tags the audit
// row (input:unscanned_<kind>=<n>), block refuses the request.
//
// They are counted in the turns the gateway scans: the trailing turn with
// SCAN_HISTORY=latest, every turn on chat completions. Text, documents whose
// source is text or content, and search results are scanned and not counted.

// unscannedKind maps a content part or block type with no text to its kind.
func unscannedKind(partType string) string {
	switch partType {
	case "image", "image_url", "input_image":
		return "image"
	case "file", "input_file", "document", "container_upload":
		return "file"
	case "input_audio", "audio":
		return "audio"
	}
	return "other"
}

// noteUnscanned counts a part the gateway forwards without reading it.
func (g *textGuard) noteUnscanned(partType string) {
	if g.history {
		return // an earlier turn: not scanned, so not counted either
	}
	if g.unscanned == nil {
		g.unscanned = map[string]int{}
	}
	g.unscanned[unscannedKind(partType)]++
}

// unscannedVars returns input.unscanned.kinds, in the order of
// indirect.UnscannedKinds, and input.unscanned.count.
func unscannedVars(counts map[string]int) ([]string, int) {
	var kinds []string
	n := 0
	for _, kind := range indirect.UnscannedKinds {
		if counts[kind] > 0 {
			kinds = append(kinds, kind)
			n += counts[kind]
		}
	}
	return kinds, n
}

// unscannedTags renders the counts for the audit row, as
// "input:unscanned_<kind>=<n>".
func unscannedTags(counts map[string]int) []string {
	var tags []string
	for _, kind := range indirect.UnscannedKinds {
		if n := counts[kind]; n > 0 {
			tags = append(tags, fmt.Sprintf("input:unscanned_%s=%d", kind, n))
		}
	}
	return tags
}

// countUnscanned records the parts in the metrics.
func countUnscanned(mode string, counts map[string]int) {
	for kind, n := range counts {
		metrics.UnscannedParts.WithLabelValues(kind, mode).Add(float64(n))
	}
}

// unscannedMessage is the refusal of a request with unscanned parts.
func unscannedMessage(counts map[string]int) string {
	kinds, _ := unscannedVars(counts)
	return "Request blocked: it contains content the guard cannot scan (" + strings.Join(kinds, ", ") +
		"). Send the extracted text instead."
}
