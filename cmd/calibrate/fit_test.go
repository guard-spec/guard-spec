// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"testing"

	"github.com/guard-spec/guard-spec/internal/evalset"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
)

// The cap of the v5 round 2 arm B calibration (RF-437128e9): 0.89 is the
// largest grid value below the block threshold with the l1,l2 combiner
// (0.91 with l1,l2,l3), less one step.
func TestUntrustedMax(t *testing.T) {
	lrs := map[string]fusion.LogReg{
		"l1,l2":    {W: [3]float64{0.4947, 0.9370, 0}, B: 0.4441},
		"l1,l2,l3": {W: [3]float64{0.4747, 0.9044, 0.3989}, B: 0.6363},
	}
	got := untrustedMax(lrs, 0.142)
	if math.Abs(got-0.88) > 1e-9 {
		t.Fatalf("untrustedMax = %.2f, want 0.88", got)
	}
	// L2 alone at the cap does not block on either path; one step up does on one.
	p1 := fusion.DefaultL1Calibration.Apply(0.142)
	p3 := ml.DefaultL3Calibration.Apply(0.5)
	for key, lr := range lrs {
		layers := [3]float64{p1, got, p3}
		if key == "l1,l2" {
			layers[fusion.L3] = fusion.Missing
		}
		if s, _ := lr.Apply(layers); s >= evalset.InjectionBlockThreshold {
			t.Errorf("%s: L2 alone at the cap blocks (%.3f)", key, s)
		}
	}
	if untrustedMax(nil, 0.142) != 0 {
		t.Error("no combiner: a cap")
	}
	// A silent L1 that scores higher leaves less room.
	if higher := untrustedMax(lrs, 0.4); higher >= got {
		t.Errorf("cap %.2f at L1 0.4, want below %.2f", higher, got)
	}
}

func TestL1Silent(t *testing.T) {
	var rows []scoredRow
	for i := 0; i < 100; i++ {
		rows = append(rows, scoredRow{Raw: [3]float64{float64(i) / 1000, 0, 0}, L1Rules: 0})
	}
	rows = append(rows, scoredRow{Raw: [3]float64{0.9, 0, 0}, L1Rules: 2}) // a rule: not silent
	if got := l1Silent(rows); math.Abs(got-0.09) > 1e-9 {
		t.Fatalf("q90 of silent rows = %.3f, want 0.090", got)
	}
	// Attacks never count, whatever their rule count (an old cache has none).
	old := []scoredRow{{Raw: [3]float64{0.5, 0, 0}, Attack: true}, {Raw: [3]float64{0.1, 0, 0}}, {Raw: [3]float64{0.2, 0, 0}}}
	if got := l1Silent(old); got != 0.2 {
		t.Fatalf("old cache: %.3f, want 0.2", got)
	}
	if l1Silent(nil) != 0 {
		t.Error("no rows: a level")
	}
}
