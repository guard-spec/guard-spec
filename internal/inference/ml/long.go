// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// WindowClassifier is a Classifier that can cut a long text into token
// windows and score windows of many texts in shared batches (*onnx.Classifier).
type WindowClassifier interface {
	Classifier
	LongWindows(text string) ([]onnx.TokenWindow, int, error)
	ScoreLongBatch(ctx context.Context, wins []onnx.TokenWindow) ([][]float32, error)
	TokenCount(text string) (int, error)
}

// windows returns the layer's classifier when it scores token windows.
func (l *ClassifierLayer) windows() (WindowClassifier, bool) {
	if l == nil {
		return nil, false
	}
	wc, ok := l.c.(WindowClassifier)
	return wc, ok
}

// ScoreLong implements inference.LongDetector with the current generation's
// fuser and classifier. Shadow mode does not compare long texts.
func (l *Live) ScoreLong(ctx context.Context, in []inference.LongInput, o inference.LongOptions) ([]inference.LongResult, inference.LongStats, error) {
	g := l.acquire()
	defer g.inflight.Done()
	var layer *ClassifierLayer
	if g.l2 != nil {
		layer = g.l2.Layer
	}
	return ScoreLong(ctx, l.stack.longFuser(g.fuser, g.l2), layer, in, o)
}

// LongFuser is the fuser of the long path: the stack's without L3, fused the
// way the stack fuses when L3 is not installed (the classifier's logistic
// regression for l1,l2 when it has one, else max).
func (s *Stack) LongFuser() *fusion.Fuser { return s.longFuser(s.Fuser, s.l2) }

func (s *Stack) longFuser(f *fusion.Fuser, m *L2Model) *fusion.Fuser {
	if !f.Has(fusion.L3) {
		return f
	}
	lf := f.Without(fusion.L3)
	if s.cfg.Fusion == "logreg" {
		active := s.Active
		active[fusion.L2], active[fusion.L3] = m != nil, false
		if lr, ok := combinerFor(m, LayerKey(active)); ok {
			lf.SetCombiner(&lr)
		} else {
			lf.SetCombiner(nil)
		}
	}
	return lf
}

// CountTokens implements inference.LongDetector: the classifier's tokens,
// or the 4-bytes-per-token estimate without one.
func (l *Live) CountTokens(text string) (int, error) {
	g := l.acquire()
	defer g.inflight.Done()
	var layer *ClassifierLayer
	if g.l2 != nil {
		layer = g.l2.Layer
	}
	if wc, ok := layer.windows(); ok {
		return wc.TokenCount(text)
	}
	return inference.EstimateTokens(text), nil
}

// ScoreLong is the long path (see internal/inference/long.go) over a fuser
// and its L2 layer (nil: none):
//
//   - each text is tokenized once and cut into the classifier's windows;
//   - identical windows (same tokens, same text) are scored once per call;
//   - L1 runs on every window's text first; windows are then scored in
//     batches of o.BatchSize, those with an L1 signal first, up to
//     o.Limiter.Cap() batches at a time, each batch under o.Limiter;
//   - each window is fused from its L1 and L2 verdicts with L3 left out
//     (fusion.Fuser.Finish), and a text's score is its largest window score;
//   - a text whose window reaches its threshold is decided: its windows not
//     yet scored are skipped.
//
// A model failure fails the call: the long path does not fall back to L1
// alone. Without a classifier that scores token windows, it is
// inference.ScoreLongChunks over the fuser with L3 left out.
func ScoreLong(ctx context.Context, f *fusion.Fuser, l2 *ClassifierLayer, in []inference.LongInput,
	o inference.LongOptions) ([]inference.LongResult, inference.LongStats, error) {
	wc, ok := l2.windows()
	if !ok || !f.Has(fusion.L2) {
		return inference.ScoreLongChunks(ctx, func(ctx context.Context, text string) (inference.Score, error) {
			return inference.FusedScore(f.ScoreWithout(ctx, text, fusion.L3)), nil
		}, in, o)
	}
	if o.BatchSize <= 0 {
		o.BatchSize = inference.DefaultLongBatch
	}
	workers := 1
	if o.Limiter != nil {
		workers = max(1, o.Limiter.Cap())
	}

	// Windows, deduplicated.
	type unit struct {
		win  onnx.TokenWindow
		text string
		pt   fusion.Partial
		res  fusion.Result
	}
	var (
		st         inference.LongStats
		units      []*unit
		owners     [][]int
		index      = map[[sha256.Size]byte]int{}
		perText    = make([][]int, len(in))
		thresholds = make([]float64, len(in))
	)
	for i, x := range in {
		thresholds[i] = x.Threshold
		wins, n, err := wc.LongWindows(x.Text)
		if err != nil {
			return nil, st, fmt.Errorf("ml: long text %d: %w", i, err)
		}
		if !st.Count(x, n, o) {
			return nil, st, inference.ErrInputTooLong
		}
		for _, w := range wins {
			st.Windows++
			span := x.Text[w.Start:w.End]
			key := windowKey(w.IDs, span)
			u, ok := index[key]
			if ok {
				st.Duplicates++
			} else {
				u = len(units)
				index[key] = u
				units = append(units, &unit{win: w, text: span})
				owners = append(owners, nil)
			}
			if k := len(owners[u]); k == 0 || owners[u][k-1] != i {
				owners[u] = append(owners[u], i)
			}
			perText[i] = append(perText[i], u)
		}
	}

	// L1 on every window, workers at a time: rules only, no model.
	if err := parallel(ctx, workers, len(units), func(u int) {
		units[u].pt = f.Begin(ctx, units[u].text)
	}); err != nil {
		return nil, st, err
	}

	// Windows the cascade decided need no model run; they go first, then
	// the others with the strongest L1 signal first.
	var quick, model []int
	for u, x := range units {
		if f.WantsL2(x.pt) {
			model = append(model, u)
		} else {
			quick = append(quick, u)
		}
	}
	sort.SliceStable(model, func(a, b int) bool {
		return units[model[a]].pt.L1Raw() > units[model[b]].pt.L1Raw()
	})
	var batches [][]int
	for _, list := range [][]int{quick, model} {
		for start := 0; start < len(list); start += o.BatchSize {
			batches = append(batches, list[start:min(start+o.BatchSize, len(list))])
		}
	}

	// A window's score as a text sees it: adjusted for a text with an
	// Adjust (on the long path L3 is absent, so only L1 or a floor can
	// corroborate a code-like window, see indirect.CorroborateCode).
	scoreFor := func(u, t int) inference.Score {
		return in[t].Adjust.Apply(units[u].text, inference.FusedScore(units[u].res))
	}
	scored, err := inference.RunLongBatchesOwned(ctx, workers, owners, thresholds, batches,
		func(ctx context.Context, us []int) ([]float64, error) {
			out := make([]float64, len(us))
			if !f.WantsL2(units[us[0]].pt) {
				for i, u := range us {
					units[u].res = f.Finish(units[u].pt, fusion.LayerResult{}, nil)
					out[i] = units[u].res.Score
				}
				return out, nil
			}
			wins := make([]onnx.TokenWindow, len(us))
			for i, u := range us {
				wins[i] = units[u].win
			}
			if o.Limiter != nil {
				if err := o.Limiter.Acquire(ctx); err != nil {
					return nil, err
				}
			}
			probs, err := wc.ScoreLongBatch(ctx, wins)
			if o.Limiter != nil {
				o.Limiter.Release()
			}
			if err != nil {
				return nil, fmt.Errorf("ml: L2 on long text: %w", err)
			}
			if len(probs) != len(us) {
				return nil, fmt.Errorf("ml: classifier returned %d rows for %d windows", len(probs), len(us))
			}
			for i, u := range us {
				units[u].res = f.Finish(units[u].pt, l2.result(probs[i]), nil)
				out[i] = units[u].res.Score
			}
			return out, nil
		}, func(u, t int, s float64) float64 {
			if in[t].Adjust == nil {
				return s
			}
			return float64(scoreFor(u, t).Confidence)
		})
	if err != nil {
		return nil, st, err
	}
	for _, ok := range scored {
		if ok {
			st.Scored++
		} else {
			st.Skipped++
		}
	}

	// A text's score is its strongest window, the first of equal ones.
	out := make([]inference.LongResult, len(in))
	for i, us := range perText {
		var best *fusion.Result
		var bestAdj inference.Score
		for _, u := range us {
			if !scored[u] {
				out[i].EarlyExit = true
				continue
			}
			r := &units[u].res
			if in[i].Adjust == nil {
				if best == nil || r.Score > best.Score {
					best = r
				}
				continue
			}
			if s := scoreFor(u, i); best == nil || s.Confidence > bestAdj.Confidence {
				best, bestAdj = r, s
			}
		}
		switch {
		case best == nil:
		case in[i].Adjust == nil:
			out[i].Score = inference.FusedScore(*best)
		default:
			out[i].Score = bestAdj
		}
	}
	return out, st, nil
}

// windowKey identifies a window by its tokens and its text.
func windowKey(ids []int64, text string) [sha256.Size]byte {
	h := sha256.New()
	var b [8]byte
	for _, id := range ids {
		binary.LittleEndian.PutUint64(b[:], uint64(id))
		h.Write(b[:])
	}
	h.Write([]byte{0})
	h.Write([]byte(text))
	var k [sha256.Size]byte
	h.Sum(k[:0])
	return k
}

// parallel runs fn(0..n-1) on up to workers goroutines; it stops handing out
// work when ctx is done and returns ctx's error then.
func parallel(ctx context.Context, workers, n int, fn func(i int)) error {
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(max(1, workers), max(1, n)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	var err error
feed:
	for i := range n {
		select {
		case next <- i:
		case <-ctx.Done():
			err = ctx.Err()
			break feed
		}
	}
	close(next)
	wg.Wait()
	return err
}
