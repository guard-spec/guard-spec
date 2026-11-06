// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// scanExplain is the "explain" object of /guardrail/scan (for text and for
// each document) and of /guardrail/scan/tools (for each tool). It is added
// only when the request sets "explain": true and SCAN_EXPLAIN is not false,
// so responses stay as they were for callers that do not ask.
type scanExplain struct {
	// Layers holds the calibrated score of each detection layer; null when
	// the layer did not run (not installed, light mode, or skipped by the
	// cascade).
	Layers explainLayers `json:"layers"`
	// DecidedBy names what set the verdict: l1, l2, l3 (the strongest layer
	// of the fused score), sanitizer (the anomaly score blocked) or signals
	// (MCP poisoning signals of a tool description).
	DecidedBy string `json:"decided_by"`
	// Reason says how: fusion, cascade (L1 decisive, L2/L3 skipped),
	// l1_floor (a decisive L1 rule set the floor of the fused score),
	// anomaly or mcp_signals.
	Reason   string   `json:"reason"`
	Category string   `json:"category,omitempty"`
	Rules    []string `json:"rules,omitempty"`
}

type explainLayers struct {
	L1 *float64 `json:"l1"`
	L2 *float64 `json:"l2"`
	L3 *float64 `json:"l3"`
}

// Values of scanExplain.Reason.
const (
	reasonFusion   = "fusion"
	reasonCascade  = "cascade"
	reasonL1Floor  = "l1_floor"
	reasonAnomaly  = "anomaly"
	reasonSignals  = "mcp_signals"
	decidedBySan   = "sanitizer"
	decidedBySigns = "signals"
)

// layerScore is a layer's score for JSON: nil when the layer did not run.
func layerScore(v float64) *float64 {
	if v < 0 { // fusion.Missing
		return nil
	}
	return &v
}

// explainScores explains one verdict. s is the detector's output for the
// text, final the score the verdict used (the detector score, or a tool's
// score raised by MCP signals), blockAt the threshold that applied and
// anomaly whether the sanitizer's anomaly score reached its own threshold.
func explainScores(s inference.Scores, final, blockAt float64, anomaly bool) *scanExplain {
	inj := float64(s.Injection.Confidence)
	out := &scanExplain{Reason: reasonFusion, DecidedBy: modelLayer(s)}
	if d := s.Injection.Detail; d != nil {
		out.Layers = explainLayers{L1: layerScore(d.L1), L2: layerScore(d.L2), L3: layerScore(d.L3)}
		out.Category, out.Rules = d.Category, d.Rules
		switch {
		case d.Cascaded:
			out.DecidedBy, out.Reason = "l1", reasonCascade
		case slices.Contains(d.Rules, fusion.L1FloorRule):
			out.DecidedBy, out.Reason = "l1", reasonL1Floor
		}
	} else {
		// A backend without fusion detail (the legacy regex detector): its
		// score is L1's.
		out.Layers.L1 = layerScore(inj)
	}
	switch {
	// inj went through float32; a raise below its precision is not one.
	case final > inj+1e-6 && final >= blockAt:
		out.DecidedBy, out.Reason = decidedBySigns, reasonSignals
	case anomaly && final < blockAt:
		out.DecidedBy, out.Reason = decidedBySan, reasonAnomaly
	}
	return out
}
