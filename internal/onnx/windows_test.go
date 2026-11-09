package onnx

import (
	"context"
	"errors"
	"testing"
)

func TestScoreWindowsOffsetsAndWorstCase(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{MaxLength: 10, Stride: 2, BatchSize: 3, MaxChunks: -1})
	// 8 content tokens per window, step 6; 40 + 1 + 3 = 44 tokens.
	text := words(40) + " " + bad + " " + words(3)
	ws, err := c.ScoreWindows(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 7 {
		t.Fatalf("got %d windows, want 7", len(ws))
	}
	for i, w := range ws {
		wantEnd := min(i*6+8, 44)
		if w.Start != i*6 || w.End != wantEnd {
			t.Errorf("window %d: [%d,%d), want [%d,%d)", i, w.Start, w.End, i*6, wantEnd)
		}
	}
	inj := c.LabelIndex("INJECTION")
	for i, w := range ws {
		hit := w.Start <= 40 && 40 < w.End // the payload is token 40
		if (w.Probs[inj] > 0.5) != hit {
			t.Errorf("window %d [%d,%d): INJECTION=%v, want high=%v", i, w.Start, w.End, w.Probs[inj], hit)
		}
	}
	got, err := c.Score(context.Background(), []string{text})
	if err != nil {
		t.Fatal(err)
	}
	assertWorstCase(t, c, ws, got[0])

	if ws, err := c.ScoreWindows(context.Background(), ""); err != nil || len(ws) != 1 || ws[0].Start != 0 || ws[0].End != 0 {
		t.Fatalf("empty text: %+v %v", ws, err)
	}
}

func TestScoreWindowsCap(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{MaxLength: 6, Stride: 1, MaxChunks: 2})
	if _, err := c.ScoreWindows(context.Background(), words(50)); !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("want ErrInputTooLong, got %v", err)
	}
}

// assertWorstCase checks that Score's row for a text is the per-label worst
// case over its ScoreWindows: the minimum for the benign label, the maximum
// for every other label.
func assertWorstCase(t *testing.T, c *Classifier, ws []WindowScore, score []float32) {
	t.Helper()
	for k := range c.Labels() {
		agg := ws[0].Probs[k]
		for _, w := range ws[1:] {
			if k == c.BenignIndex() {
				agg = min(agg, w.Probs[k])
			} else {
				agg = max(agg, w.Probs[k])
			}
		}
		if agg != score[k] {
			t.Errorf("label %s: worst case over windows %v, Score %v", c.Labels()[k], agg, score[k])
		}
	}
}
