// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// capCal is a calibration like v5's: identity Platt, the shipped v4
// combiners and a cap of 0.88.
func capCal() CalibrationFile {
	c := BuiltinCalibrations["guardspec-classifier-v4"]
	c.Platt = fusion.Identity
	c.L2UntrustedMax = 0.88
	return c
}

func detail(l1, l2, l3, floor float64, rules ...string) inference.Score {
	layers := [3]float64{l1, l2, l3}
	var s float64
	if lr, ok := capCal().LogReg[LayerKey([3]bool{l1 != fusion.Missing, l2 != fusion.Missing, l3 != fusion.Missing})]; ok {
		s = fusion.Recombine(layers, floor, &lr)
	} else {
		s = fusion.Recombine(layers, floor, nil)
	}
	return inference.Score{Label: "jailbreak", Confidence: float32(s),
		Detail: &inference.Detail{L1: l1, L2: l2, L3: l3, Floor: floor, Category: "jailbreak", Rules: rules}}
}

func TestCapL2(t *testing.T) {
	silent := fusion.DefaultL1Calibration.Apply(0.14) // no rule fired
	rule := fusion.DefaultL1Calibration.Apply(0.7)    // a rule fired
	neutral := DefaultL3Calibration.Apply(0.5)
	adj := CapL2(capCal(), true)
	if adj == nil {
		t.Fatal("no adjust for a calibration with a cap")
	}
	for _, tt := range []struct {
		name  string
		in    inference.Score
		lower bool
		max   float64 // the capped score stays below this
	}{
		{"L2 alone, short path", detail(silent, 0.995, neutral, 0, "l2:jailbreak"), true, 0.85},
		{"L2 alone, long path (no L3)", detail(silent, 0.995, fusion.Missing, 0, "l2:jailbreak"), true, 0.85},
		{"L1 rule lifts it past the threshold", detail(rule, 0.995, neutral, 0, "de.dump_secrets", "l2:jailbreak"), true, 1},
		{"L3 lifts it", detail(silent, 0.995, 0.9, 0, "l2:jailbreak", "l3:jailbreak"), true, 1},
		{"below the cap: unchanged", detail(silent, 0.8, neutral, 0, "l2:jailbreak"), false, 1},
		{"no L2: unchanged", detail(rule, fusion.Missing, neutral, 0, "pe.reveal"), false, 1},
		{"floor kept as the lower bound", detail(silent, 0.995, neutral, 0.99, "di.override.chained", "fusion.l1_floor"), false, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := adj("chunk", tt.in)
			if lowered := got.Confidence < tt.in.Confidence; lowered != tt.lower {
				t.Fatalf("score %.3f -> %.3f, lowered %v, want %v", tt.in.Confidence, got.Confidence, lowered, tt.lower)
			}
			if got.Confidence > tt.in.Confidence {
				t.Fatal("score raised")
			}
			if float64(got.Confidence) < tt.in.Detail.Floor {
				t.Fatalf("score %.3f below the floor %.3f", got.Confidence, tt.in.Detail.Floor)
			}
			if !tt.lower {
				if slices.Contains(got.Detail.Rules, fusion.L2CapRule) {
					t.Errorf("rule %s added without a change", fusion.L2CapRule)
				}
				return
			}
			if float64(got.Confidence) >= tt.max {
				t.Errorf("capped score %.3f, want below %.2f", got.Confidence, tt.max)
			}
			if !slices.Contains(got.Detail.Rules, fusion.L2CapRule) || slices.Contains(tt.in.Detail.Rules, fusion.L2CapRule) {
				t.Errorf("rules in %v out %v", tt.in.Detail.Rules, got.Detail.Rules)
			}
			if got.Detail.L2 != tt.in.Detail.L2 {
				t.Error("the reported L2 score changed; only the fused score should")
			}
			// Parity: the capped score is what the fuser gives with L2 at the cap.
			layers := [3]float64{tt.in.Detail.L1, 0.88, tt.in.Detail.L3}
			lr := capCal().LogReg[LayerKey([3]bool{true, true, tt.in.Detail.L3 != fusion.Missing})]
			if want := fusion.Recombine(layers, tt.in.Detail.Floor, &lr); float64(got.Confidence) < want-1e-6 || float64(got.Confidence) > want+1e-6 {
				t.Errorf("capped score %.6f, fuser with L2 at the cap %.6f", got.Confidence, want)
			}
		})
	}
	// Below the category threshold the label goes with the score.
	low := detail(silent, 0.995, fusion.Missing, 0, "l2:jailbreak")
	maxOnly := CapL2(CalibrationFile{Platt: fusion.Identity, L2UntrustedMax: 0.2}, false)
	if got := maxOnly("c", low); got.Label != "BENIGN" || got.Detail.Category != "" || got.Confidence > 0.3 {
		t.Errorf("max fusion, cap 0.2: %+v %+v", got, got.Detail)
	}
	// With max fusion the capped L2 is one layer among the others.
	if got := CapL2(CalibrationFile{Platt: fusion.Identity, L2UntrustedMax: 0.88}, false)("c", detail(0.95, 0.995, fusion.Missing, 0)); got.Confidence != 0.95 {
		t.Errorf("max fusion keeps L1's 0.95, got %.3f", got.Confidence)
	}
}

// Without the field nothing changes: the built-in calibrations, the shipped
// v3b file and a file that does not set it give no adjust.
func TestCapL2OffByDefault(t *testing.T) {
	for name, c := range BuiltinCalibrations {
		if c.L2UntrustedMax != 0 || CapL2(c, true) != nil {
			t.Errorf("%s: built-in calibration has a cap", name)
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "models", "local", "guardspec-classifier-v3b", calibrationFile))
	if err == nil {
		var f CalibrationFile
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		if f.L2UntrustedMax != 0 {
			t.Errorf("shipped v3b calibration.json sets l2_untrusted_max %v", f.L2UntrustedMax)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, calibrationFile), []byte(`{"model":"x","platt":{"A":1,"B":0}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cal, _ := calibrationFor(dir, "x")
	if CapL2(cal, true) != nil {
		t.Error("a calibration.json without l2_untrusted_max gives an adjust")
	}
	if (&Stack{}).UntrustedAdjust() != nil {
		t.Error("a stack without L2 gives an adjust")
	}
	for _, v := range []float64{0, -1, 1, 1.5} {
		if CapL2(CalibrationFile{L2UntrustedMax: v}, true) != nil {
			t.Errorf("cap %v gives an adjust", v)
		}
	}
}

// A reload that brings a calibration with a cap changes the live adjust.
func TestLiveUntrustedAdjustFollowsReload(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.2, "v3b": 0.7})
	cal := filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", "v3b", calibrationFile)
	if err := os.WriteFile(cal, []byte(`{"model":"v3b","platt":{"A":1,"B":0},"l2_untrusted_max":0.5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	l := e.live(t, "v2", ShadowConfig{})
	adj := l.UntrustedAdjust()
	in := inference.Score{Label: "jailbreak", Confidence: 0.9, Detail: &inference.Detail{L1: 0.1, L2: 0.9, L3: fusion.Missing, Category: "jailbreak"}}
	if got := adj("c", in); got.Confidence != 0.9 {
		t.Fatalf("v2 has no cap, score %.3f", got.Confidence)
	}
	if _, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@v3b"}); err != nil {
		t.Fatal(err)
	}
	if got := adj("c", in); !near(float64(got.Confidence), 0.5) || !slices.Contains(got.Detail.Rules, fusion.L2CapRule) {
		t.Fatalf("after reload: score %.3f rules %v, want 0.5 (max fusion, L2 at the cap)", got.Confidence, got.Detail.Rules)
	}
}
