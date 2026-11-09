// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// capAdjust lowers every chunk score to 0.1 and records the chunks it saw.
type capAdjust struct {
	mu   sync.Mutex
	seen []string
}

func (c *capAdjust) fn(chunk string, s Score) Score {
	c.mu.Lock()
	c.seen = append(c.seen, chunk)
	c.mu.Unlock()
	s.Confidence = min(s.Confidence, 0.1)
	return s
}

// On the short path the adjustment applies per chunk before the max; a nil
// adjustment leaves Scan's result as it was.
func TestScanAdjustedShortPath(t *testing.T) {
	r := NewRunnerWith(&hashBackend{})
	text := strings.Repeat("a", 3000) + " " + payload + " " + strings.Repeat("b", 3000)
	plain, err := r.Scan(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	same, err := r.ScanAdjusted(context.Background(), text, nil)
	if err != nil || !reflect.DeepEqual(plain, same) {
		t.Fatalf("nil adjust changed the result: %+v / %+v (%v)", plain, same, err)
	}
	c := &capAdjust{}
	adj, err := r.ScanAdjusted(context.Background(), text, c.fn)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Injection.Confidence < 0.9 || adj.Injection.Confidence > 0.1 {
		t.Fatalf("plain %.2f, adjusted %.2f", plain.Injection.Confidence, adj.Injection.Confidence)
	}
	chunks, _ := chunkText(text, 512, 448)
	if len(c.seen) != len(chunks) {
		t.Fatalf("adjust saw %d chunks, want %d", len(c.seen), len(chunks))
	}
}

// On the long path the adjustment applies per chunk of the text that asked
// for it, before early exit: a shared chunk keeps its own score for a text
// without one, and a LongScan keeps the two results apart.
func TestScoreLongChunksAdjust(t *testing.T) {
	b := &hashBackend{}
	pad := strings.Repeat("p", 1792)
	attack := strings.Repeat(pad, 3) + payload + strings.Repeat(pad, 40)
	c := &capAdjust{}
	in := []LongInput{{Text: attack, Threshold: 0.9}, {Text: attack, Threshold: 0.9, Adjust: c.fn}}
	lim := testLimiter{make(chan struct{}, 1)}
	res, _, err := ScoreLongChunks(context.Background(), func(ctx context.Context, t string) (Score, error) {
		s, err := b.Run(ctx, t)
		return s[0], err
	}, in, LongOptions{Limiter: lim})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Score.Confidence != 0.99 {
		t.Fatalf("unadjusted text: %+v", res[0])
	}
	// The adjusted text never reaches its threshold, so every chunk is scored.
	if res[1].Score.Confidence > 0.1 || res[1].EarlyExit {
		t.Fatalf("adjusted text: %+v", res[1])
	}

	r := NewRunnerWith(&hashBackend{})
	ls := NewLongScan(LongOptions{})
	ctx := WithLongScan(context.Background(), ls)
	if err := r.Prescore(ctx, ls, []LongInput{{Text: attack, Adjust: c.fn}}); err != nil {
		t.Fatal(err)
	}
	scored := ls.Stats().Scored
	adj, err := r.ScanAdjusted(ctx, attack, c.fn)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Stats().Scored != scored || adj.Injection.Confidence > 0.1 {
		t.Fatalf("adjusted scan was not served from Prescore: %+v, stats %+v", adj.Injection, ls.Stats())
	}
	plain, err := r.Scan(ctx, attack)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Injection.Confidence != 0.99 {
		t.Fatalf("plain scan got the adjusted result: %+v", plain.Injection)
	}
}
