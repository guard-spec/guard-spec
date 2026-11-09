// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// The long path (inference.Runner.ScanLong, ml.LongScorer) scores a text past
// the short path's limit window by window. It tokenizes the text once, keeps
// the byte span of every window so the rule layer can read the same text, and
// runs the windows of every long text of a request in shared batches, under a
// limiter of its own. Every token is in at least one window; nothing is
// truncated.

// ErrNoOffsets means the tokenizer cannot map tokens back to the text.
var ErrNoOffsets = errors.New("onnx: tokenizer gives no offsets")

// offsetTokenizer is a tokenizer that also returns the byte span [start,end)
// of every content token in the text.
type offsetTokenizer interface {
	EncodeOffsets(text string) ([]int64, [][2]int, error)
}

// TokenWindow is one window of a long text: its model input (special tokens
// and prefix included) and the byte span [Start,End) of the text it covers.
type TokenWindow struct {
	IDs        []int64
	Start, End int
	Tokens     int // content tokens
}

// LongWindows tokenizes text once and cuts it into windows of the model's
// length that overlap by its stride, like Score does, but without the
// MaxChunks cap: the caller bounds the tokens (MAX_SCAN_TOKENS). The spans
// cover the whole text: the first window starts at 0, the last ends at
// len(text), and neighbours overlap. It returns the number of content tokens.
func (c *Classifier) LongWindows(text string) ([]TokenWindow, int, error) {
	m := c.m
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, 0, ErrClosed
	}
	ot, ok := m.tok.(offsetTokenizer)
	if !ok {
		return nil, 0, ErrNoOffsets
	}
	ids, offs, err := ot.EncodeOffsets(text)
	if err != nil {
		return nil, 0, err
	}
	if len(offs) != len(ids) {
		return nil, 0, fmt.Errorf("onnx: %d offsets for %d tokens", len(offs), len(ids))
	}
	return m.longWindows(text, ids, offs), len(ids), nil
}

func (m *model) longWindows(text string, ids []int64, offs [][2]int) []TokenWindow {
	window := m.maxLen - len(m.prefix) - len(m.suffix)
	step := window - m.stride
	var out []TokenWindow
	for start := 0; ; start += step {
		end := min(start+window, len(ids))
		seq := make([]int64, 0, len(m.prefix)+end-start+len(m.suffix))
		seq = append(seq, m.prefix...)
		seq = append(seq, ids[start:end]...)
		seq = append(seq, m.suffix...)
		w := TokenWindow{IDs: seq, Tokens: end - start}
		if end > start {
			w.Start, w.End = offs[start][0], offs[end-1][1]
		}
		if start == 0 {
			w.Start = 0
		}
		if end == len(ids) {
			w.End = len(text)
		}
		w.Start, w.End = spanIn(text, w.Start, w.End)
		out = append(out, w)
		if end == len(ids) {
			return out
		}
	}
}

// spanIn clamps [start,end) to text and widens it to rune boundaries.
func spanIn(text string, start, end int) (int, int) {
	start = max(0, min(start, len(text)))
	end = max(start, min(end, len(text)))
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return start, end
}

// ScoreLongBatch runs one batch of windows (from LongWindows, of any texts)
// and returns per-label probabilities per window, activated as Score does.
// It does not take the model's limiter: the long path bounds its runs with a
// limiter of its own (INFERENCE_LARGE_MAX_CONCURRENCY).
func (c *Classifier) ScoreLongBatch(ctx context.Context, wins []TokenWindow) ([][]float32, error) {
	m := c.m
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	if len(wins) == 0 {
		return nil, nil
	}
	seq := 0
	for _, w := range wins {
		seq = max(seq, len(w.IDs))
	}
	n := len(wins)
	ids := make([]int64, n*seq)
	mask := make([]int64, n*seq)
	typeIDs := make([]int64, n*seq)
	for r, w := range wins {
		row := ids[r*seq : (r+1)*seq]
		copy(row, w.IDs)
		for j := len(w.IDs); j < seq; j++ {
			row[j] = m.pad
		}
		for j := range w.IDs {
			mask[r*seq+j] = 1
		}
	}
	data, shape, err := m.sess.Run(ctx, ids, mask, typeIDs, n, seq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	nl := len(c.labels)
	if len(shape) != 2 || int(shape[0]) != n || int(shape[1]) != nl {
		return nil, fmt.Errorf("onnx: classifier output shape %v, want [%d %d]", shape, n, nl)
	}
	activate := softmax
	if c.head == HeadSigmoid {
		activate = sigmoid
	}
	out := make([][]float32, n)
	for r := range wins {
		out[r] = activate(data[r*nl : (r+1)*nl])
	}
	return out, nil
}
