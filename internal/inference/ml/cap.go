// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// The classifier's cap for untrusted content (CalibrationFile.L2UntrustedMax).
//
// The classifier is trained on attack payloads embedded in code and log
// hosts against the same hosts without a payload, so a block of foreign
// prose inside code or a log makes it certain (a calibrated score above
// 0.99) whether or not the prose is an attack (RF-437128e9: on eval/embedded
// benign rows that is a third of the rows, with the other layers silent).
// Its calibration cannot tell the two apart, since the validation splits hold
// no such benign rows; the rule and similarity layers can. So on untrusted
// content the calibrated L2 score counts up to the cap only: a chunk (or a
// long-path window) is fused again with L2 at the cap, with the combiner of
// the layers that ran, and keeps the lower score. The cap is chosen so that
// L2 alone, with L1 silent and L3 neutral, stays below the block threshold
// on both paths; L1 or L3 lift still blocks. Floors (a decisive L1 verdict,
// an org's own exemplar) are kept, the score is never raised, and the
// direct path (user and system text, tool descriptions) is not affected.

// minCategoryScore matches fusion: below it no category is named.
const minCategoryScore = 0.3

// CapL2 is the inference.ChunkAdjust of cal's untrusted-content cap: nil when
// cal sets none. logreg says whether fusion uses the calibration's combiners
// (the stack's Fusion); with max the capped L2 is simply one of the layers.
func CapL2(cal CalibrationFile, logreg bool) inference.ChunkAdjust {
	limit := cal.L2UntrustedMax
	if limit <= 0 || limit >= 1 {
		return nil
	}
	return func(_ string, s inference.Score) inference.Score {
		d := s.Detail
		if d == nil || d.L2 == fusion.Missing || d.L2 <= limit {
			return s
		}
		layers := [3]float64{d.L1, d.L2, d.L3}
		layers[fusion.L2] = limit
		var comb *fusion.LogReg
		if logreg {
			// The combiner of the layers that ran, as the stack picks it:
			// l1,l2,l3 on the short path, l1,l2 on the long path (no L3).
			active := [3]bool{d.L1 != fusion.Missing, true, d.L3 != fusion.Missing}
			if lr, ok := cal.LogReg[LayerKey(active)]; ok {
				comb = &lr
			}
		}
		score := fusion.Recombine(layers, d.Floor, comb)
		if score >= float64(s.Confidence)-1e-6 { // Confidence is a float32
			return s
		}
		nd := *d
		nd.Rules = append(append([]string(nil), d.Rules...), fusion.L2CapRule)
		s.Detail = &nd
		s.Confidence = float32(score)
		if score < minCategoryScore {
			nd.Category = ""
			s.Label = "BENIGN"
		}
		return s
	}
}

// UntrustedAdjust is the cap of the stack's classifier as an
// inference.ChunkAdjust (indirect.Scanner.CapL2): nil without a classifier or
// without a cap in its calibration. A Live detector follows its reloads
// (Live.UntrustedAdjust).
func (s *Stack) UntrustedAdjust() inference.ChunkAdjust {
	if s.l2 == nil {
		return nil
	}
	return CapL2(s.l2.Cal, s.Fusion == "logreg")
}

// UntrustedAdjust is Stack.UntrustedAdjust for the running generation: the
// returned function reads the classifier in place at each call, so a reload
// that brings another calibration changes the cap with it. It is never nil;
// without a cap it leaves scores unchanged.
func (l *Live) UntrustedAdjust() inference.ChunkAdjust {
	return func(chunk string, s inference.Score) inference.Score {
		g := l.acquire()
		defer g.inflight.Done()
		if g.l2 == nil {
			return s
		}
		if adj := CapL2(g.l2.Cal, g.fusion == "logreg"); adj != nil {
			return adj(chunk, s)
		}
		return s
	}
}
