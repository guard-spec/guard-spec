// Package fusion combines the detection layers into one calibrated
// injection score:
//
//   - L1: the rule engine (package rules), always present;
//   - L2: a classifier (ONNX, task N2), optional;
//   - L3: an embedding similarity layer, optional.
//
// Method: "max of calibrated scores". Each layer's raw score s is mapped to a
// probability with Platt scaling on the logit,
//
//	p = sigmoid(A * logit(s) + B)
//
// and the fused injection score is the largest p of the layers that ran.
// Per-category scores are the largest calibrated category score across layers.
// A, B are fitted per layer on a calibration split that is separate from
// eval/ (testdata/calibration.jsonl for L1; see TestL1CalibrationIsFitted).
//
// Max was chosen over a learned combination because layers arrive one at a
// time: a missing layer simply drops out of the max, so fusion degrades to
// the remaining layers without refitting. When L2 and L3 exist and a joint
// calibration split has scores for all three, logistic regression on the
// three logits can replace max without changing this API.
package fusion

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/promptshield/promptshield/internal/inference/rules"
	"github.com/promptshield/promptshield/internal/metrics"
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
}

// Fuser holds the layers and their calibrations. It is safe for concurrent
// use when the layers are.
type Fuser struct {
	layers [numLayers]Layer
	cal    [numLayers]Calibration
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

// Score runs every configured layer. A layer that is absent or fails is
// reported as Missing and left out of the max; the result then rests on the
// layers that ran. With no layer at all the score is 0.
func (f *Fuser) Score(ctx context.Context, text string) Result {
	res := Result{Categories: map[string]float64{}}
	best := -1.0
	for slot, l := range f.layers {
		res.Layers[slot] = Missing
		if l == nil {
			continue
		}
		start := time.Now()
		lr, err := l.Score(ctx, text)
		metrics.DetectorDuration.WithLabelValues(layerNames[slot]).Observe(time.Since(start).Seconds())
		if err != nil {
			metrics.DetectorErrors.WithLabelValues(layerNames[slot]).Inc()
			slog.Warn("detection layer failed; fusing the others", "layer", slot+1, "err", err)
			continue
		}
		c := f.cal[slot]
		p := c.Apply(lr.Score)
		res.Layers[slot] = p
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
	if res.Score < minCategoryScore {
		res.Category = ""
	}
	return res
}

// RulesLayer adapts the L1 rule engine.
type RulesLayer struct{ E *rules.Engine }

// Score implements Layer.
func (r RulesLayer) Score(_ context.Context, text string) (LayerResult, error) {
	res := r.E.Score(text)
	return LayerResult{Score: res.Score, Category: res.Category, Categories: res.Categories, Rules: res.Rules}, nil
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
		a -= da
		b -= db
		if math.Abs(da) < 1e-9 && math.Abs(db) < 1e-9 {
			break
		}
	}
	return Calibration{A: a, B: b}
}
