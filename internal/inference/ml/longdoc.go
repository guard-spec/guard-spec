// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"math"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// The long document rule (RF-895d3533 R3).
//
// On the long path a text's score is its strongest window, so a benign
// document of 100k tokens (about 500 windows) is blocked when any one of its
// windows reaches the threshold: on bench/long that was one benign document
// in four for v6, although at most 0.4% of its units scored that high. The
// rule decides such a document from its windows by its length: past
// LongDoc.MinWindows windows, a window over the threshold counts only when
// the rules agree (Corroborate), or when it clears a threshold that grows
// with the number of windows (Threshold), or either. It is applied to each
// window's score after the document adjustment (the cap, code
// corroboration), before early exit and the max, so a text is still decided
// by its strongest window, now as the rule sees it. Texts of at most
// MinWindows windows, the short path and calibrations without long_doc are
// unchanged.

// corroborationL1Raw is the raw L1 score of a fired rule that corroborates a
// window (the bar of code corroboration, indirect.CorroborateCode).
const corroborationL1Raw = 0.5

// corroborationL1 is corroborationL1Raw on the calibrated scale of Detail.L1.
var corroborationL1 = fusion.DefaultL1Calibration.Apply(corroborationL1Raw)

// L1Corroborates reports whether the rules agree with a window's score: L1
// fired a rule with a raw score of at least 0.5 (every decisive rule does),
// or a floor applied.
func L1Corroborates(s inference.Score) bool {
	d := s.Detail
	if d == nil {
		return false
	}
	return d.L1 >= corroborationL1 || d.Floor > 0
}

// LongDocRule is the inference.LongDocRule of a calibration's LongDoc.
type LongDocRule struct{ p LongDoc }

// NewLongDocRule returns the rule of p; nil when p is nil.
func NewLongDocRule(p *LongDoc) *LongDocRule {
	if p == nil {
		return nil
	}
	return &LongDocRule{p: *p}
}

// Params are the rule's parameters.
func (r *LongDocRule) Params() LongDoc { return r.p }

// shift is logit T(n) - logit Base: how much a window's logit is lowered in
// a text of n windows (0: none).
func (r *LongDocRule) shift(n int) float64 {
	t := r.p.Threshold
	if len(t) == 0 || r.p.Base <= 0 || r.p.Base >= 1 || float64(n) < t[0][0] {
		return 0
	}
	lt := t[len(t)-1][1]
	for i := 1; i < len(t); i++ {
		if float64(n) <= t[i][0] {
			f := (math.Log(float64(n)) - math.Log(t[i-1][0])) / (math.Log(t[i][0]) - math.Log(t[i-1][0]))
			lt = sigmoid((1-f)*logit(t[i-1][1]) + f*logit(t[i][1]))
			break
		}
	}
	return max(0, logit(lt)-logit(r.p.Base))
}

// Threshold is T(n), the score a window of a text of n windows needs to
// count as Base does in a short text (Base without a Threshold).
func (r *LongDocRule) Threshold(n int) float64 {
	if r.p.Base <= 0 || r.p.Base >= 1 {
		return 0
	}
	return sigmoid(logit(r.p.Base) + r.shift(n))
}

// Apply implements inference.LongDocRule: s as it counts in a text of n
// windows. The score is never raised; a lowered window names the rule.
func (r *LongDocRule) Apply(n int, s inference.Score) inference.Score {
	if r == nil || n <= r.p.MinWindows {
		return s
	}
	if r.p.Corroborate && L1Corroborates(s) {
		return s
	}
	score := float64(s.Confidence)
	switch {
	case len(r.p.Threshold) > 0:
		score = sigmoid(logit(score) - r.shift(n))
	case r.p.Corroborate && s.Detail != nil && s.Detail.L1 != fusion.Missing:
		score = min(score, s.Detail.L1)
	default:
		return s
	}
	if score >= float64(s.Confidence)-1e-6 { // Confidence is a float32
		return s
	}
	s.Confidence = float32(score)
	if s.Detail != nil {
		nd := *s.Detail
		nd.Rules = append(append([]string(nil), nd.Rules...), fusion.LongDocRule)
		if score < minCategoryScore {
			nd.Category = ""
		}
		s.Detail = &nd
	}
	if score < minCategoryScore {
		s.Label = "BENIGN"
	}
	return s
}

func logit(p float64) float64 {
	p = min(max(p, 1e-9), 1-1e-9)
	return math.Log(p / (1 - p))
}

// LongDocRule is the long document rule of the stack's classifier: nil when
// its calibration has none.
func (s *Stack) LongDocRule() *LongDocRule {
	if s.l2 == nil {
		return nil
	}
	return NewLongDocRule(s.l2.Cal.LongDoc)
}
