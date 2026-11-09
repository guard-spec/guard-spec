package inference

import (
	"context"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// Detail explains a fused injection score. Layer scores are calibrated
// probabilities, or fusion.Missing (-1) when the layer did not run.
type Detail struct {
	L1, L2, L3 float64
	Category   string             // top category, "" when nothing matched
	Categories map[string]float64 // per-category scores
	Rules      []string           // fired rule ids
	// Floor is the lower bound a floor layer or a decisive L1 verdict set
	// on the score (fusion.Result.Floor); 0 when none did.
	Floor float64
}

// Scorer is what FusedBackend runs: a *fusion.Fuser, or a detector that can
// swap its fuser at run time (ml.Live).
type Scorer interface {
	Score(ctx context.Context, text string) fusion.Result
}

// FusedBackend scores injection with fusion over L1 rules (and L2/L3 when
// they are installed on the Fuser).
type FusedBackend struct{ F Scorer }

// Run implements ModelBackend.
func (b FusedBackend) Run(ctx context.Context, text string) ([]Score, error) {
	return []Score{FusedScore(b.F.Score(ctx, text))}, nil
}

// NewRegexRunner returns a Runner with the legacy regex detector (L1 v1),
// kept for comparison (`cmd/eval -detector regex`).
func NewRegexRunner() *Runner {
	return NewRunnerWith(&heuristicInjectionBackend{})
}
