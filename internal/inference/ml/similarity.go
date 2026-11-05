package ml

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// Exemplar labels: "block" exemplars are attacks, "allow" exemplars benign.
const (
	LabelBlock = "block"
	LabelAllow = "allow"
)

// TenantCategory is the injection.category of a match on an org's own block
// exemplar.
const TenantCategory = "tenant_exemplar"

// Exemplar is one reference text for L3.
type Exemplar struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    string `json:"label"`              // LabelBlock or LabelAllow
	Category string `json:"category,omitempty"` // attack category of a block exemplar
	Lang     string `json:"lang,omitempty"`
	Source   string `json:"source,omitempty"`
	License  string `json:"license,omitempty"`
}

// Embedder is the part of *onnx.Embedder that L3 uses. It must be built with
// the e5 "query:" prefix (see Build).
type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	EmbedWindows(ctx context.Context, texts []string) ([][][]float32, error)
}

// Index is a set of embedded exemplars.
type Index struct {
	attack    [][]float32
	attackCat []string
	benign    [][]float32
}

// Len is the number of exemplars (attack, benign).
func (ix *Index) Len() (attack, benign int) {
	if ix == nil {
		return 0, 0
	}
	return len(ix.attack), len(ix.benign)
}

// embedBatch bounds the texts per Embed call while building an index.
const embedBatch = 64

// NewIndex embeds the exemplars.
func NewIndex(ctx context.Context, e Embedder, ex []Exemplar) (*Index, error) {
	texts := make([]string, len(ex))
	for i, x := range ex {
		texts[i] = x.Text
	}
	vecs := make([][]float32, 0, len(ex))
	for start := 0; start < len(texts); start += embedBatch {
		v, err := e.Embed(ctx, texts[start:min(start+embedBatch, len(texts))])
		if err != nil {
			return nil, fmt.Errorf("ml: embed exemplars: %w", err)
		}
		vecs = append(vecs, v...)
	}
	return indexFrom(ex, vecs)
}

func indexFrom(ex []Exemplar, vecs [][]float32) (*Index, error) {
	ix := &Index{}
	for i, x := range ex {
		switch x.Label {
		case LabelBlock:
			ix.attack = append(ix.attack, vecs[i])
			ix.attackCat = append(ix.attackCat, x.Category)
		case LabelAllow:
			ix.benign = append(ix.benign, vecs[i])
		default:
			return nil, fmt.Errorf("ml: exemplar %q: label %q, want block or allow", x.ID, x.Label)
		}
	}
	return ix, nil
}

// DefaultTemperature scales the similarity margin before the raw score:
// raw = sigmoid(margin / T). e5 similarities sit in a narrow band, so the
// margin is small; the Platt calibration then rescales it.
const DefaultTemperature = 0.05

// SimilarityLayer is L3: the raw score is sigmoid(margin / T), where margin is
// the highest similarity to an attack exemplar minus the highest similarity to
// a benign exemplar, taken over the windows of the text (the worst window
// counts). An organization's exemplars (from the context, see WithOrg) join
// the default ones: block exemplars as attacks, allow exemplars as benign.
type SimilarityLayer struct {
	e       Embedder
	base    *Index
	tenants *TenantCache // nil: default exemplars only
	temp    float64
}

// NewSimilarityLayer builds L3 over an embedder and the default index.
// tenants may be nil.
func NewSimilarityLayer(e Embedder, base *Index, tenants *TenantCache) (*SimilarityLayer, error) {
	if a, _ := base.Len(); a == 0 {
		return nil, errors.New("ml: L3 needs at least one attack exemplar")
	}
	return &SimilarityLayer{e: e, base: base, tenants: tenants, temp: DefaultTemperature}, nil
}

// Score implements fusion.Layer.
func (l *SimilarityLayer) Score(ctx context.Context, text string) (fusion.LayerResult, error) {
	idx := []*Index{l.base}
	if l.tenants != nil {
		if org, ok := OrgFrom(ctx); ok {
			t, err := l.tenants.Index(ctx, org)
			if err != nil {
				return fusion.LayerResult{}, fmt.Errorf("org exemplars: %w", err)
			}
			if t != nil {
				idx = append(idx, t)
			}
		}
	}
	wins, err := l.e.EmbedWindows(ctx, []string{text})
	if err != nil {
		return fusion.LayerResult{}, err
	}
	if len(wins) != 1 || len(wins[0]) == 0 {
		return fusion.LayerResult{}, errors.New("ml: embedder returned no window")
	}
	m := match(wins[0], idx)
	res := fusion.LayerResult{
		Score:    sigmoid(m.margin / l.temp),
		Category: m.category,
	}
	// An org's own block exemplar is an explicit instruction: its match is not
	// diluted by the other layers.
	res.Floor = m.category == TenantCategory
	if m.category != "" {
		res.Categories = map[string]float64{m.category: res.Score}
		res.Rules = []string{"l3:" + m.category}
	}
	return res, nil
}

// Margin returns the raw similarity margin of a text (for calibration tools).
func (l *SimilarityLayer) Margin(ctx context.Context, text string) (float64, error) {
	wins, err := l.e.EmbedWindows(ctx, []string{text})
	if err != nil {
		return 0, err
	}
	return match(wins[0], []*Index{l.base}).margin, nil
}

type matchResult struct {
	margin   float64
	category string
}

// match is the worst window's margin and its nearest attack's category.
func match(windows [][]float32, idx []*Index) matchResult {
	best := matchResult{margin: math.Inf(-1)}
	for _, w := range windows {
		maxA, maxB := -1.0, -1.0
		cat := ""
		for _, ix := range idx {
			for i, v := range ix.attack {
				if s := dot(w, v); s > maxA {
					maxA, cat = s, ix.attackCat[i]
				}
			}
			for _, v := range ix.benign {
				maxB = max(maxB, dot(w, v))
			}
		}
		if m := maxA - maxB; m > best.margin {
			best = matchResult{margin: m, category: cat}
		}
	}
	return best
}

func dot(a, b []float32) float64 {
	var s float32
	for i := range a {
		s += a[i] * b[i]
	}
	return float64(s)
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }
