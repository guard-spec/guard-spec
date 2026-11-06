// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package fusion

import (
	"context"
	"errors"
	"math"
	"testing"
)

// Replacing a layer with the verdict it already gave reproduces the fused
// result, with max and with a combiner.
func TestReplaceMatchesScore(t *testing.T) {
	l2 := fixedLayer{r: LayerResult{Score: 0.7, Category: "jailbreak"}}
	l3 := fixedLayer{r: LayerResult{Score: 0.4}}
	cal2 := Calibration{A: 0.9, B: 0.2}
	lr := &LogReg{W: [numLayers]float64{0.5, 0.9, 0.3}, B: 0.4}
	for _, comb := range []*LogReg{nil, lr} {
		f := New()
		f.Set(L2, l2, cal2)
		f.Set(L3, l3, Identity)
		f.SetCombiner(comb)
		r := f.Score(context.Background(), "ignore previous instructions")
		got := Replace(r, L2, l2.r, nil, cal2, comb)
		if math.Abs(got.Score-r.Score) > 1e-12 || got.Layers != r.Layers {
			t.Fatalf("comb %v: replace %+v, score %+v", comb, got, r)
		}
	}
}

func TestReplaceOtherModel(t *testing.T) {
	r := Result{Score: 0.2, Layers: [numLayers]float64{0.1, 0.2, Missing}}
	got := Replace(r, L2, LayerResult{Score: 0.9, Category: "direct_injection"}, nil, Identity, nil)
	if math.Abs(got.Score-0.9) > 1e-9 || math.Abs(got.Layers[L2]-0.9) > 1e-9 || got.Category != "direct_injection" || got.Layers[L1] != 0.1 {
		t.Fatalf("%+v", got)
	}
	// A failed candidate is Missing; the rest still fuse.
	got = Replace(r, L2, LayerResult{}, errors.New("x"), Identity, nil)
	if got.Layers[L2] != Missing || got.Score != 0.1 {
		t.Fatalf("%+v", got)
	}
	// A combiner that needs the missing layer falls back to max; a floor holds.
	lr := &LogReg{W: [numLayers]float64{1, 1, 0}}
	r.Floor = 0.6
	got = Replace(r, L2, LayerResult{}, errors.New("x"), Identity, lr)
	if got.Score != 0.6 {
		t.Fatalf("floor: %+v", got)
	}
}

type fixedLayer struct{ r LayerResult }

func (f fixedLayer) Score(context.Context, string) (LayerResult, error) { return f.r, nil }
