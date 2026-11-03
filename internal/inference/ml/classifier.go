// Package ml holds the model-based detection layers that plug into
// package fusion:
//
//   - L2 (ClassifierLayer): our EN/VI attack classifier (guardspec-classifier),
//     risk = 1 - p(benign), top attack label as the category;
//   - L3 (SimilarityLayer): multilingual-e5 embeddings compared with attack
//     and benign exemplars, plus each organization's own exemplars.
//
// Both run through internal/onnx and so need the `onnx` build tag. Build
// (load.go) reads the configuration, loads what it can and reports what it
// could not, so the gateway runs on L1 alone when models are missing.
package ml

import (
	"context"
	"errors"
	"fmt"

	"github.com/promptshield/promptshield/internal/inference/fusion"
)

// Classifier is the part of *onnx.Classifier that L2 uses.
type Classifier interface {
	// Score returns per-label probabilities; a long text is windowed with
	// overlap and every label takes its worst case over the windows.
	Score(ctx context.Context, texts []string) ([][]float32, error)
	Labels() []string
	BenignIndex() int
}

// ClassifierLayer is L2: a fusion.Layer over a multi-label classifier.
type ClassifierLayer struct {
	c      Classifier
	labels []string
	benign int
}

// NewClassifierLayer wraps a classifier that has a benign label.
func NewClassifierLayer(c Classifier) (*ClassifierLayer, error) {
	if c.BenignIndex() < 0 {
		return nil, errors.New("ml: classifier has no benign label")
	}
	return &ClassifierLayer{c: c, labels: c.Labels(), benign: c.BenignIndex()}, nil
}

// Score implements fusion.Layer. The raw score is 1 - p(benign) (the lowest
// p(benign) over the windows of a long text); the category is the attack
// label with the highest probability.
func (l *ClassifierLayer) Score(ctx context.Context, text string) (fusion.LayerResult, error) {
	probs, err := l.c.Score(ctx, []string{text})
	if err != nil {
		return fusion.LayerResult{}, err
	}
	if len(probs) != 1 || len(probs[0]) != len(l.labels) {
		return fusion.LayerResult{}, fmt.Errorf("ml: classifier returned %d rows", len(probs))
	}
	p := probs[0]
	res := fusion.LayerResult{
		Score:      1 - float64(p[l.benign]),
		Categories: make(map[string]float64, len(p)-1),
	}
	best := -1.0
	for i, v := range p {
		if i == l.benign {
			continue
		}
		res.Categories[l.labels[i]] = float64(v)
		if float64(v) > best {
			best, res.Category = float64(v), l.labels[i]
		}
	}
	if res.Category != "" {
		res.Rules = []string{"l2:" + res.Category}
	}
	return res, nil
}
