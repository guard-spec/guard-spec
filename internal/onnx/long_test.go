// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
)

// offsetFake is fakeTokenizer with byte offsets.
type offsetFake struct{ fakeTokenizer }

func (f *offsetFake) EncodeOffsets(text string) ([]int64, [][2]int, error) {
	var ids []int64
	var offs [][2]int
	start := -1
	for i, r := range text + " " {
		if unicode.IsSpace(r) {
			if start >= 0 {
				ids = append(ids, int64(i-start)+10)
				offs = append(offs, [2]int{start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return ids, offs, nil
}

func newLongClassifier(t *testing.T, o Options) (*Classifier, *fakeSession) {
	t.Helper()
	tok, sess := &offsetFake{}, &fakeSession{}
	m, err := newModel(tok, sess, modelConfig{}, o)
	if err != nil {
		t.Fatal(err)
	}
	return newClassifier(m, []string{"SAFE", "INJECTION"}, HeadSoftmax), sess
}

func TestLongWindowsMatchChunksAndCoverText(t *testing.T) {
	c, _ := newLongClassifier(t, Options{MaxLength: 6, Stride: 1, MaxChunks: 2})
	text := "  ab c dé ffff g hh iii j kk l mmm  "
	wins, n, err := c.LongWindows(text)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := c.m.tok.Encode(text)
	if n != len(ids) {
		t.Fatalf("tokens = %d, want %d", n, len(ids))
	}
	// The same windows as Score's chunking, without its MaxChunks cap.
	c.m.maxChunks = -1
	chunks, err := c.m.chunk(ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(wins) != len(chunks) || len(wins) <= 2 {
		t.Fatalf("%d windows, chunk gives %d", len(wins), len(chunks))
	}
	covered := 0
	for i, w := range wins {
		if !slices.Equal(w.IDs, chunks[i]) {
			t.Fatalf("window %d ids %v, want %v", i, w.IDs, chunks[i])
		}
		if w.Start > covered {
			t.Fatalf("window %d starts at %d, text covered to %d", i, w.Start, covered)
		}
		covered = max(covered, w.End)
		// The span holds exactly the window's content tokens.
		got, _ := c.m.tok.Encode(text[w.Start:w.End])
		want := w.IDs[1 : len(w.IDs)-1]
		if !slices.Equal(got, want) {
			t.Fatalf("window %d span %q encodes to %v, want %v", i, text[w.Start:w.End], got, want)
		}
	}
	if wins[0].Start != 0 || covered != len(text) {
		t.Fatalf("spans cover [%d,%d) of %d bytes", wins[0].Start, covered, len(text))
	}
}

func TestLongWindowsNeedOffsets(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{MaxLength: 6, Stride: 1})
	if _, _, err := c.LongWindows("a b c"); !errors.Is(err, ErrNoOffsets) {
		t.Fatalf("err = %v, want ErrNoOffsets", err)
	}
}

func TestScoreLongBatchMatchesScore(t *testing.T) {
	c, sess := newLongClassifier(t, Options{MaxLength: 8, Stride: 2})
	texts := []string{words(3), words(2) + " " + bad, words(6)}
	var wins []TokenWindow
	for _, txt := range texts {
		w, _, err := c.LongWindows(txt)
		if err != nil {
			t.Fatal(err)
		}
		wins = append(wins, w...)
	}
	got, err := c.ScoreLongBatch(context.Background(), wins)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.Score(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range texts {
		if !slices.Equal(got[i], want[i]) {
			t.Fatalf("text %d: batch %v, Score %v", i, got[i], want[i])
		}
	}
	if b := sess.batches[0]; b[0] != len(wins) {
		t.Fatalf("first run had %d rows, want all %d windows", b[0], len(wins))
	}
	if c.Close() != nil {
		t.Fatal("close")
	}
	if _, err := c.ScoreLongBatch(context.Background(), wins); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
	if _, _, err := c.LongWindows(strings.Repeat("a ", 3)); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}

// Under WithLimiter, model runs take the given limiter's slots instead of the
// model's own: the large-input lane bounds every run of a large request.
func TestWithLimiterReplacesModelLimiter(t *testing.T) {
	c, sess, _ := newFakeClassifier(t, Options{Limiter: NewLimiter(4), MaxLength: 6, Stride: 1})
	sess.delay = 20 * time.Millisecond
	ctx := WithLimiter(context.Background(), NewLimiter(1))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Score(ctx, []string{"a b c"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if p := sess.peak.Load(); p != 1 {
		t.Fatalf("peak concurrency %d under a limiter of 1", p)
	}
	if LimiterFrom(context.Background(), nil) != nil {
		t.Fatal("LimiterFrom without a limiter in ctx")
	}
}
