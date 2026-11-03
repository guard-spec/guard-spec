package onnx

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestSigmoidHeadAndWorstCaseAggregation uses a three-label multi-label head
// (benign, direct_injection, jailbreak). The fake session gives logits
// [-x, x, 0] where x is +10 when the window holds the "bad" token, else -10.
func TestSigmoidHeadAndWorstCaseAggregation(t *testing.T) {
	m, err := newModel(&fakeTokenizer{}, &threeLabelSession{}, modelConfig{},
		Options{MaxLength: 10, Stride: 2, MaxChunks: -1, Limiter: NewLimiter(2)})
	if err != nil {
		t.Fatal(err)
	}
	c := newClassifier(m, []string{"benign", "direct_injection", "jailbreak"}, HeadSigmoid)
	if c.BenignIndex() != 0 || c.Head() != HeadSigmoid {
		t.Fatalf("benign %d head %v", c.BenignIndex(), c.Head())
	}
	texts := []string{"hello there", words(40) + " " + bad}
	got, err := c.Score(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	// One window, no payload: independent sigmoids, not a softmax.
	if p := got[0]; !near(p[0], sig(10)) || !near(p[1], sig(-10)) || !near(p[2], 0.5) {
		t.Fatalf("sigmoid probabilities %v", p)
	}
	// Payload in a later window: benign takes the minimum, attacks the maximum.
	if p := got[1]; !near(p[0], sig(-10)) || !near(p[1], sig(10)) {
		t.Fatalf("chunked worst case %v", p)
	}
	risk, err := c.Risk(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	if risk[0] > 0.01 || risk[1] < 0.99 {
		t.Fatalf("risk %v", risk)
	}
}

func TestRiskNeedsBenignLabel(t *testing.T) {
	m, err := newModel(&fakeTokenizer{}, &fakeSession{}, modelConfig{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := newClassifier(m, []string{"A", "B"}, HeadSoftmax)
	if _, err := c.Risk(context.Background(), []string{"x"}); !errors.Is(err, ErrNoBenignLabel) {
		t.Fatalf("want ErrNoBenignLabel, got %v", err)
	}
	if c.BenignIndex() != -1 {
		t.Fatal("no benign label expected")
	}
}

func TestResolveModelFileAndTrainedMaxLen(t *testing.T) {
	dir := t.TempDir()
	if got := ResolveModelFile(dir, Options{}); filepath.Base(got) != ModelFile {
		t.Fatalf("empty dir: %s", got)
	}
	if err := os.WriteFile(filepath.Join(dir, ModelInt8File), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveModelFile(dir, Options{}); filepath.Base(got) != ModelInt8File {
		t.Fatalf("int8 only: %s", got)
	}
	if got := ResolveModelFile(dir, Options{ModelFile: "x.onnx"}); filepath.Base(got) != "x.onnx" {
		t.Fatalf("override: %s", got)
	}
	if n := trainedMaxLen(dir); n != 0 {
		t.Fatalf("no thresholds.json: %d", n)
	}
	if err := os.WriteFile(filepath.Join(dir, ThresholdsFile), []byte(`{"max_len": 256}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := trainedMaxLen(dir); n != 256 {
		t.Fatalf("trainedMaxLen %d", n)
	}
}

func sig(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

func near(a float32, b float64) bool { return math.Abs(float64(a)-b) < 1e-6 }

type threeLabelSession struct{ fakeSession }

func (s *threeLabelSession) Run(ctx context.Context, ids, mask, typeIDs []int64, batch, seq int) ([]float32, []int64, error) {
	two, _, err := s.fakeSession.Run(ctx, ids, mask, typeIDs, batch, seq)
	if err != nil {
		return nil, nil, err
	}
	out := make([]float32, batch*3)
	for r := 0; r < batch; r++ {
		x := two[2*r+1] // +10 with payload, -10 without
		out[3*r] = -x
		out[3*r+1] = x
	}
	return out, []int64{int64(batch), 3}, nil
}
