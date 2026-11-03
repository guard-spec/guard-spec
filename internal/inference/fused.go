package inference

import (
	"context"

	"github.com/giaplee/guard-spec/internal/inference/fusion"
)

// Detail explains a fused injection score. Layer scores are calibrated
// probabilities, or fusion.Missing (-1) when the layer did not run.
type Detail struct {
	L1, L2, L3 float64
	Category   string             // top category, "" when nothing matched
	Categories map[string]float64 // per-category scores
	Rules      []string           // fired rule ids
}

// FusedBackend scores injection with fusion over L1 rules (and L2/L3 when
// they are installed on the Fuser).
type FusedBackend struct{ F *fusion.Fuser }

// Run implements ModelBackend.
func (b FusedBackend) Run(ctx context.Context, text string) ([]Score, error) {
	r := b.F.Score(ctx, text)
	label := "BENIGN"
	if r.Category != "" {
		label = r.Category
	}
	return []Score{{
		Label:      label,
		Confidence: float32(r.Score),
		Detail: &Detail{
			L1: r.Layers[fusion.L1], L2: r.Layers[fusion.L2], L3: r.Layers[fusion.L3],
			Category: r.Category, Categories: r.Categories, Rules: r.Rules,
		},
	}}, nil
}

// NewRegexRunner returns a Runner with the legacy regex detector (L1 v1),
// kept for comparison (`cmd/eval -detector regex`).
func NewRegexRunner() *Runner {
	return NewRunnerWith(&heuristicInjectionBackend{})
}
