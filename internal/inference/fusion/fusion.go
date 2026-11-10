// Package fusion combines the detection layers into one calibrated
// injection score:
//
//   - L1: the rule engine (package rules), always present;
//   - L2: a classifier (ONNX, task N2), optional;
//   - L3: an embedding similarity layer, optional.
//
// Base method: "max of calibrated scores". Each layer's raw score s is mapped to a
// probability with Platt scaling on the logit,
//
//	p = sigmoid(A * logit(s) + B)
//
// and the fused injection score is the largest p of the layers that ran.
// Per-category scores are the largest calibrated category score across layers.
// A, B are fitted per layer on a calibration split that is separate from
// eval/ (testdata/calibration.jsonl for L1; see TestL1CalibrationIsFitted).
//
// With L2 and L3 installed (package ml) the default combiner is a logistic
// regression over the calibrated layer logits (SetCombiner), fitted on the
// classifier's validation split: there it beat max on log loss, Brier score,
// AUC and TPR at 1% FPR in 5-fold cross-validation (cmd/calibrate fit). When
// a weighted layer did not run (failed, or skipped by the cascade), that
// request falls back to max, so fusion still degrades to the layers that ran.
//
// L1 floor (SetL1Floor): the combiner weights L1 at about 0.46 against 0.91
// for L2, so a classifier that is sure a text is benign outvotes even a
// certain rule match. When L1 fires a decisive rule (an override followed by
// its payload, rules.Result.Decisive) and its calibrated score reaches the
// floor, that score becomes a lower bound of the fused score, like a layer
// with LayerResult.Floor.
//
// L1 runs first; L2 and L3 then run in parallel. With a Cascade, L2 and L3 are
// skipped when L1's calibrated score is already decisive.
package fusion

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference/rules"
	"github.com/guard-spec/guard-spec/internal/metrics"
)

// Layer slots.
const (
	L1 = iota
	L2
	L3
	numLayers
)

// layerNames are the metric labels of the slots.
var layerNames = [numLayers]string{"l1", "l2", "l3"}

// Missing is the per-layer score of a layer that did not run.
const Missing = -1.0

// LayerResult is one layer's raw verdict.
type LayerResult struct {
	Score      float64            // raw score in [0,1]
	Category   string             // top category, "" if none
	Categories map[string]float64 // raw per-category scores, may be nil
	Rules      []string           // explanation (rule ids, nearest exemplar, ...)
	// Floor makes this layer's calibrated score a lower bound of the fused
	// score, whatever the combiner; for an explicit match such as an
	// organization's own block exemplar.
	Floor bool
	// Decisive marks an L1 verdict that rests on a decisive rule; with
	// SetL1Floor it bounds the fused score from below.
	Decisive bool
}

// Layer is a detector stage. L2 and L3 implement it later.
type Layer interface {
	Score(ctx context.Context, text string) (LayerResult, error)
}

// Calibration is a Platt scaling on the logit of the raw score.
type Calibration struct{ A, B float64 }

// Identity leaves scores unchanged.
var Identity = Calibration{A: 1, B: 0}

// Apply maps a raw score to a calibrated probability.
func (c Calibration) Apply(s float64) float64 {
	return sigmoid(c.A*logit(s) + c.B)
}

// Result is the fused verdict.
type Result struct {
	Score      float64            // calibrated injection score (the gateway's injection.score)
	Layers     [numLayers]float64 // calibrated per-layer scores; Missing when a layer did not run
	Category   string             // category of the strongest layer; "" when nothing matched
	Categories map[string]float64 // calibrated per-category scores
	Rules      []string           // explanation from every layer that ran
	// Floor is the largest calibrated score of a layer that set
	// LayerResult.Floor, or of a decisive L1 verdict at or above the L1 floor
	// (0 when none); the fused score is never below it.
	Floor float64
	// L1Floored is true when the L1 floor applied (Floor holds L1's score).
	L1Floored bool
	// Cascaded is true when the cascade found L1 decisive and skipped the
	// other layers.
	Cascaded bool
}

// Fuser holds the layers and their calibrations. It is safe for concurrent
// use when the layers are. Configure it (Set, SetCascade, SetCombiner) before
// the first Score.
type Fuser struct {
	layers  [numLayers]Layer
	cal     [numLayers]Calibration
	cascade *Cascade
	combine *LogReg
	l1Floor float64 // 0: off
}

// L1FloorRule is the explanation added to Result.Rules when the L1 floor
// raised the fused score.
const L1FloorRule = "fusion.l1_floor"

// L2CapRule is the explanation added to a chunk's rules when the
// classifier's cap for untrusted content lowered its score (ml.CapL2).
const L2CapRule = "fusion.l2_capped"

// SetL1Floor makes a decisive L1 verdict whose calibrated score is at least
// min a lower bound of the fused score. 0 turns it off.
func (f *Fuser) SetL1Floor(min float64) { f.l1Floor = min }

// L1Floor is the floor set by SetL1Floor (0: off).
func (f *Fuser) L1Floor() float64 { return f.l1Floor }

// Cascade skips L2 and L3 when L1's calibrated score is decisive: at least
// High, or at most Low. A skipped layer is reported as Missing.
type Cascade struct{ Low, High float64 }

// SetCascade turns the cascade on (nil turns it off).
func (f *Fuser) SetCascade(c *Cascade) { f.cascade = c }

// SetCombiner replaces max with a logistic regression over the calibrated
// layer logits (nil goes back to max). When a layer with a non-zero weight did
// not run, that request falls back to max.
func (f *Fuser) SetCombiner(lr *LogReg) { f.combine = lr }

// Without returns a copy of f with the slot's layer removed; the copy keeps
// f's calibrations, cascade, combiner and L1 floor until they are set on it.
func (f *Fuser) Without(slot int) *Fuser {
	c := *f
	c.layers[slot] = nil
	return &c
}

// Has reports whether a layer is installed in the slot.
func (f *Fuser) Has(slot int) bool { return f.layers[slot] != nil }

// LogReg is p = sigmoid(B + sum_i W[i] * logit(p_i)) over the calibrated
// per-layer scores p_i.
type LogReg struct {
	W [numLayers]float64
	B float64
}

// Apply combines calibrated layer scores. ok is false when a weighted layer is
// Missing.
func (lr LogReg) Apply(p [numLayers]float64) (score float64, ok bool) {
	z := lr.B
	for i, w := range lr.W {
		if w == 0 {
			continue
		}
		if p[i] == Missing {
			return 0, false
		}
		z += w * logit(p[i])
	}
	return sigmoid(z), true
}

// New returns a fuser with the default L1 rule engine and its calibration.
func New() *Fuser {
	f := &Fuser{}
	f.Set(L1, RulesLayer{E: rules.New()}, DefaultL1Calibration)
	return f
}

// Set installs (or, with a nil layer, removes) the layer in a slot.
func (f *Fuser) Set(slot int, l Layer, c Calibration) {
	f.layers[slot] = l
	f.cal[slot] = c
}

// minCategoryScore keeps weak category scores out of the explanation.
const minCategoryScore = 0.3

// Score runs every configured layer: L1 first, then L2 and L3 in parallel
// (unless the cascade finds L1 decisive). A layer that is absent, skipped or
// fails is reported as Missing and left out; the result then rests on the
// layers that ran. With no layer at all the score is 0.
func (f *Fuser) Score(ctx context.Context, text string) Result {
	return f.score(ctx, text, -1)
}

// ScoreWithout is Score with the layer in slot left out for this text: it is
// reported as Missing, and with the combiner the text falls back to max when
// the slot has a weight (as when a layer fails). The long path
// (inference.Runner.ScanLong) leaves out L3 this way.
func (f *Fuser) ScoreWithout(ctx context.Context, text string, slot int) Result {
	return f.score(ctx, text, slot)
}

// pass holds one text's layer verdicts before fusion.
type pass struct {
	out  [numLayers]LayerResult
	errs [numLayers]error
	ran  [numLayers]bool
	skip bool // the cascade found L1 decisive
}

func (f *Fuser) runLayer(ctx context.Context, p *pass, slot int, text string) {
	start := time.Now()
	p.out[slot], p.errs[slot] = f.layers[slot].Score(ctx, text)
	metrics.DetectorDuration.WithLabelValues(layerNames[slot]).Observe(time.Since(start).Seconds())
	p.ran[slot] = true
}

// first runs L1 and decides the cascade.
func (f *Fuser) first(ctx context.Context, text string) pass {
	var p pass
	if f.layers[L1] != nil {
		f.runLayer(ctx, &p, L1, text)
	}
	if c := f.cascade; c != nil && p.ran[L1] && p.errs[L1] == nil {
		cal := f.cal[L1].Apply(p.out[L1].Score)
		p.skip = cal >= c.High || cal <= c.Low
	}
	return p
}

// score is Score with the layer in slot without left out (-1: none).
func (f *Fuser) score(ctx context.Context, text string, without int) Result {
	p := f.first(ctx, text)
	if !p.skip {
		var rest []int
		for slot := L1 + 1; slot < numLayers; slot++ {
			if f.layers[slot] != nil && slot != without {
				rest = append(rest, slot)
			}
		}
		if len(rest) == 1 {
			f.runLayer(ctx, &p, rest[0], text)
		} else if len(rest) > 1 {
			var wg sync.WaitGroup
			for _, slot := range rest {
				wg.Add(1)
				go func() {
					defer wg.Done()
					f.runLayer(ctx, &p, slot, text)
				}()
			}
			wg.Wait()
		}
	}
	return f.fuse(p.out, p.errs, p.ran, p.skip)
}

// Partial is a text whose L1 verdict is known and whose L2 verdict the
// caller gets itself, in a batch with other texts (the long path). Begin
// makes one; Finish fuses it.
type Partial struct{ p pass }

// Begin runs L1 on text and decides the cascade: the first half of Score,
// for a caller that runs L2 itself.
func (f *Fuser) Begin(ctx context.Context, text string) Partial {
	return Partial{p: f.first(ctx, text)}
}

// L1Raw is the raw L1 score of a Partial (0 when L1 did not run or failed).
// The long path scores windows with an L1 signal first.
func (pt Partial) L1Raw() float64 {
	if !pt.p.ran[L1] || pt.p.errs[L1] != nil {
		return 0
	}
	return pt.p.out[L1].Score
}

// WantsL2 reports whether Finish needs an L2 verdict for pt: L2 is installed
// and the cascade did not find L1 decisive.
func (f *Fuser) WantsL2(pt Partial) bool { return f.layers[L2] != nil && !pt.p.skip }

// Finish fuses a Partial with the L2 verdict the caller got: lr, or err when
// L2 failed (left out, as a failed layer is in Score). They are ignored when
// WantsL2 is false. L3 is left out, as with ScoreWithout(ctx, text, L3).
func (f *Fuser) Finish(pt Partial, lr LayerResult, err error) Result {
	p := pt.p
	if f.WantsL2(pt) {
		p.out[L2], p.errs[L2], p.ran[L2] = lr, err, true
	}
	return f.fuse(p.out, p.errs, p.ran, p.skip)
}

// fuse combines one text's layer verdicts.
func (f *Fuser) fuse(out [numLayers]LayerResult, errs [numLayers]error, ran [numLayers]bool, skip bool) Result {
	res := Result{Categories: map[string]float64{}, Cascaded: skip}
	best := -1.0
	for slot := range f.layers {
		res.Layers[slot] = Missing
		if !ran[slot] {
			continue
		}
		if err := errs[slot]; err != nil {
			metrics.DetectorErrors.WithLabelValues(layerNames[slot]).Inc()
			slog.Warn("detection layer failed; fusing the others", "layer", slot+1, "err", err)
			continue
		}
		lr := out[slot]
		c := f.cal[slot]
		p := c.Apply(lr.Score)
		res.Layers[slot] = p
		if lr.Floor && p > res.Floor {
			res.Floor = p
		}
		if slot == L1 && f.l1Floor > 0 && lr.Decisive && p >= f.l1Floor && p > res.Floor {
			res.Floor = p
			res.L1Floored = true
		}
		if p > best {
			best = p
			res.Score = p
			res.Category = lr.Category
		}
		for cat, s := range lr.Categories {
			if cs := c.Apply(s); cs >= minCategoryScore && cs > res.Categories[cat] {
				res.Categories[cat] = cs
			}
		}
		res.Rules = append(res.Rules, lr.Rules...)
	}
	if f.combine != nil {
		if s, ok := f.combine.Apply(res.Layers); ok {
			res.Score = s
		}
		if res.Floor > res.Score {
			if res.L1Floored {
				res.Rules = append(res.Rules, L1FloorRule)
			}
			res.Score = res.Floor
		}
	}
	if res.Score < minCategoryScore {
		res.Category = ""
	}
	return res
}

// Recombine fuses calibrated per-layer scores again, as fuse does once the
// layers have run: comb (nil: max) over the layers that are not Missing,
// never below floor. When comb weights a Missing layer the result is the max,
// as in fuse. A caller that lowers one layer's calibrated score after fusion
// (ml.CapL2) gets the score the fuser would have given.
func Recombine(layers [numLayers]float64, floor float64, comb *LogReg) float64 {
	score := 0.0
	for _, p := range layers {
		if p != Missing && p > score {
			score = p
		}
	}
	if comb != nil {
		if s, ok := comb.Apply(layers); ok {
			score = s
		}
	}
	return math.Max(score, floor)
}

// Replace fuses r again with another verdict in one slot: lr, calibrated with
// c, or Missing when err is set. comb is the combiner to use (nil: max), as
// SetCombiner would install it. The other layers keep their calibrated scores
// from r, so a candidate model can be compared with the active one on the
// same request without running L1 and L3 twice. Categories are not
// recomputed; Category is lr's when the slot is the strongest layer.
func Replace(r Result, slot int, lr LayerResult, err error, c Calibration, comb *LogReg) Result {
	out := Result{Layers: r.Layers, Floor: r.Floor, Cascaded: r.Cascaded, Category: r.Category}
	out.Layers[slot] = Missing
	if err == nil {
		out.Layers[slot] = c.Apply(lr.Score)
	}
	best := -1.0
	bestSlot := -1
	for i, p := range out.Layers {
		if p != Missing && p > best {
			best, bestSlot = p, i
		}
	}
	if bestSlot >= 0 {
		out.Score = best
	}
	if comb != nil {
		if s, ok := comb.Apply(out.Layers); ok {
			out.Score = s
		}
		if out.Floor > out.Score {
			out.Score = out.Floor
		}
	}
	if bestSlot == slot {
		out.Category = lr.Category
	}
	if out.Score < minCategoryScore {
		out.Category = ""
	}
	return out
}

// RulesLayer adapts the L1 rule engine.
type RulesLayer struct{ E *rules.Engine }

// Score implements Layer.
func (r RulesLayer) Score(_ context.Context, text string) (LayerResult, error) {
	res := r.E.Score(text)
	return LayerResult{Score: res.Score, Category: res.Category, Categories: res.Categories, Rules: res.Rules,
		Decisive: res.Decisive}, nil
}

const eps = 1e-4

func logit(p float64) float64 {
	p = math.Min(math.Max(p, eps), 1-eps)
	return math.Log(p / (1 - p))
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

// FitPlatt fits A, B by Newton's method on the log loss of
// sigmoid(A*logit(s)+B) against the labels, with Platt's target smoothing so
// a perfectly separated split does not push A to infinity.
func FitPlatt(scores []float64, attack []bool) Calibration {
	var npos, nneg float64
	for _, a := range attack {
		if a {
			npos++
		} else {
			nneg++
		}
	}
	hi, lo := (npos+1)/(npos+2), 1/(nneg+2)
	a, b := 1.0, 0.0
	for iter := 0; iter < 100; iter++ {
		var ga, gb, haa, hab, hbb float64
		for i, s := range scores {
			x := logit(s)
			y := lo
			if attack[i] {
				y = hi
			}
			p := sigmoid(a*x + b)
			d := p - y
			w := math.Max(p*(1-p), 1e-12)
			ga += d * x
			gb += d
			haa += w * x * x
			hab += w * x
			hbb += w
		}
		haa += 1e-9
		hbb += 1e-9
		det := haa*hbb - hab*hab
		if det == 0 {
			break
		}
		da := (hbb*ga - hab*gb) / det
		db := (haa*gb - hab*ga) / det
		// Backtracking line search (Lin, Lin and Weng 2007): a full Newton
		// step can overshoot when scores pile up at 0 or 1.
		cur := plattLoss(scores, attack, a, b, hi, lo)
		step := 1.0
		for ; step > 1e-10; step /= 2 {
			if plattLoss(scores, attack, a-step*da, b-step*db, hi, lo) <= cur+1e-12 {
				break
			}
		}
		a -= step * da
		b -= step * db
		if math.Abs(step*da) < 1e-9 && math.Abs(step*db) < 1e-9 {
			break
		}
	}
	return Calibration{A: a, B: b}
}

// plattLoss is the smoothed-target log loss FitPlatt minimises.
func plattLoss(scores []float64, attack []bool, a, b, hi, lo float64) float64 {
	var l float64
	for i, s := range scores {
		y := lo
		if attack[i] {
			y = hi
		}
		z := a*logit(s) + b
		// log(1+e^z) - y*z, computed stably
		l += math.Max(z, 0) + math.Log1p(math.Exp(-math.Abs(z))) - y*z
	}
	return l
}

// Logit is the log-odds used on scores everywhere in fusion (clamped to
// [1e-4, 1-1e-4]).
func Logit(p float64) float64 { return logit(p) }

// FitLogReg fits a LogReg on calibrated layer scores by Newton's method on the
// log loss, with an L2 penalty lambda on the weights (not the bias). Only the
// layers in use get a weight; their scores must not be Missing.
func FitLogReg(p [][numLayers]float64, attack []bool, use [numLayers]bool, lambda float64) LogReg {
	var idx []int
	for i, u := range use {
		if u {
			idx = append(idx, i)
		}
	}
	d := len(idx) + 1 // weights, then bias
	theta := make([]float64, d)
	x := make([]float64, d)
	for iter := 0; iter < 100; iter++ {
		g := make([]float64, d)
		h := make([][]float64, d)
		for i := range h {
			h[i] = make([]float64, d)
		}
		for n, row := range p {
			for k, i := range idx {
				x[k] = logit(row[i])
			}
			x[d-1] = 1
			z := 0.0
			for k := range x {
				z += theta[k] * x[k]
			}
			q := sigmoid(z)
			y := 0.0
			if attack[n] {
				y = 1
			}
			w := math.Max(q*(1-q), 1e-12)
			for a := range x {
				g[a] += (q - y) * x[a]
				for b := range x {
					h[a][b] += w * x[a] * x[b]
				}
			}
		}
		for a := 0; a < d-1; a++ {
			g[a] += lambda * theta[a]
			h[a][a] += lambda
		}
		h[d-1][d-1] += 1e-9
		step, ok := solve(h, g)
		if !ok {
			break
		}
		done := true
		for a := range theta {
			theta[a] -= step[a]
			if math.Abs(step[a]) > 1e-9 {
				done = false
			}
		}
		if done {
			break
		}
	}
	var lr LogReg
	for k, i := range idx {
		lr.W[i] = theta[k]
	}
	lr.B = theta[d-1]
	return lr
}

// solve returns x with a x = b by Gaussian elimination with partial pivoting.
func solve(a [][]float64, b []float64) ([]float64, bool) {
	n := len(b)
	m := make([][]float64, n)
	for i := range a {
		m[i] = append(append([]float64(nil), a[i]...), b[i])
	}
	for c := 0; c < n; c++ {
		piv := c
		for r := c + 1; r < n; r++ {
			if math.Abs(m[r][c]) > math.Abs(m[piv][c]) {
				piv = r
			}
		}
		if math.Abs(m[piv][c]) < 1e-15 {
			return nil, false
		}
		m[c], m[piv] = m[piv], m[c]
		for r := c + 1; r < n; r++ {
			f := m[r][c] / m[c][c]
			for k := c; k <= n; k++ {
				m[r][k] -= f * m[c][k]
			}
		}
	}
	x := make([]float64, n)
	for r := n - 1; r >= 0; r-- {
		s := m[r][n]
		for k := r + 1; k < n; k++ {
			s -= m[r][k] * x[k]
		}
		x[r] = s / m[r][r]
	}
	return x, true
}
