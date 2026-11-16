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

// UntrustedL1FloorRule is the explanation added to Detail.Rules when the
// untrusted-content L1 floor raised a chunk's score.
const UntrustedL1FloorRule = "fusion.untrusted_l1_floor"

// UntrustedL1Floor is the L1 floor on untrusted content (UNTRUSTED_L1_FLOOR):
// nil when min is 0.
//
// Untrusted content (a tool result, an email, a document) has no reason to
// address the model: an instruction in it is an injection whoever wrote it.
// The rule layer recognizes such instructions (sending data to an address,
// addressing the assistant, overrides, obfuscated forms of them), but the
// logistic combiner weights L1 at about half of L2, so a classifier that
// finds the email benign, or a capped one, outvotes a near-certain rule match
// (RF-67fdf675: on indirect1 dev, 225 of 1,400 attacks had a calibrated L1
// score of 0.85 or more and a fused v8e score below 0.1). With the floor, a
// chunk whose calibrated L1 score reaches min scores at least that much. The
// rule layer's own suppressors (meta discussion, quotes, code string
// literals) still apply before its score, and the code corroboration of the
// tool path is unchanged. The direct path is not affected.
func UntrustedL1Floor(min float64) inference.ChunkAdjust {
	if min <= 0 {
		return nil
	}
	return func(_ string, s inference.Score) inference.Score {
		d := s.Detail
		if d == nil || d.L1 == fusion.Missing || d.L1 < min || d.L1 <= float64(s.Confidence)+1e-6 {
			return s
		}
		nd := *d
		nd.Rules = append(append([]string(nil), d.Rules...), UntrustedL1FloorRule)
		if nd.Floor < d.L1 {
			nd.Floor = d.L1
		}
		if nd.Category == "" {
			nd.Category = topCategory(d.Categories)
		}
		s.Detail = &nd
		s.Confidence = float32(d.L1)
		if nd.Category != "" {
			s.Label = nd.Category
		}
		return s
	}
}

func topCategory(cats map[string]float64) string {
	best, name := 0.0, ""
	for c, v := range cats {
		if v > best || (v == best && c < name) {
			best, name = v, c
		}
	}
	return name
}

// chain applies a, then b; nil when both are nil.
func chain(a, b inference.ChunkAdjust) inference.ChunkAdjust {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(chunk string, s inference.Score) inference.Score { return b(chunk, a(chunk, s)) }
}

// UntrustedAdjust is the stack's adjustment of untrusted content as an
// inference.ChunkAdjust (indirect.Scanner.CapL2): the cap of its classifier,
// then the untrusted-content L1 floor; nil when neither applies. A Live
// detector follows its reloads (Live.UntrustedAdjust).
func (s *Stack) UntrustedAdjust() inference.ChunkAdjust {
	return chain(s.CapAdjust(), s.L1FloorAdjust())
}

// CapAdjust is the cap of the stack's classifier alone: nil without a
// classifier or without a cap in its calibration.
func (s *Stack) CapAdjust() inference.ChunkAdjust {
	if s.l2 == nil {
		return nil
	}
	return CapL2(s.l2.Cal, s.Fusion == "logreg")
}

// L1FloorAdjust is the untrusted-content L1 floor alone: nil when it is off
// or L1 does not run.
func (s *Stack) L1FloorAdjust() inference.ChunkAdjust {
	if !s.Active[fusion.L1] {
		return nil
	}
	return UntrustedL1Floor(s.cfg.UntrustedL1Floor)
}

// UntrustedAdjust is Stack.UntrustedAdjust for the running generation: the
// returned function reads the classifier in place at each call, so a reload
// that brings another calibration changes the cap with it. It is never nil;
// without a cap it leaves scores unchanged.
func (l *Live) UntrustedAdjust() inference.ChunkAdjust {
	return func(chunk string, s inference.Score) inference.Score {
		g := l.acquire()
		defer g.inflight.Done()
		var cp inference.ChunkAdjust
		if g.l2 != nil {
			cp = CapL2(g.l2.Cal, g.fusion == "logreg")
		}
		if l.stack.Active[fusion.L1] {
			cp = chain(cp, UntrustedL1Floor(l.stack.cfg.UntrustedL1Floor))
		}
		return cp.Apply(chunk, s)
	}
}
