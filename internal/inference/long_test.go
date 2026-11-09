// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"context"
	"errors"
	"hash/fnv"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// hashBackend gives every text a fixed pseudo-random score (high when it
// holds the payload) and counts its runs.
type hashBackend struct {
	calls atomic.Int32
	mu    sync.Mutex
	seen  map[string]int
}

func (b *hashBackend) Run(_ context.Context, text string) ([]Score, error) {
	b.calls.Add(1)
	b.mu.Lock()
	if b.seen == nil {
		b.seen = map[string]int{}
	}
	b.seen[text]++
	b.mu.Unlock()
	h := fnv.New32a()
	h.Write([]byte(text))
	c := float32(h.Sum32()%1000) / 2000 // below 0.5
	if strings.Contains(text, payload) {
		c = 0.99
	}
	return []Score{{Label: "x", Confidence: c, Detail: &Detail{Rules: []string{text[:min(8, len(text))]}}}}, nil
}

func randomText(r *rand.Rand, n int) string {
	words := []string{"lorem", "ipsum", "dolor", "sit", "amet", "ế", "tiếng", "Việt", "\n", "padding"}
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
		b.WriteByte(' ')
	}
	return b.String()[:n]
}

// The short path scores chunks in parallel and once per distinct chunk: the
// scores must be exactly those of the sequential loop it replaced.
func TestShortPathParallelMatchesSequential(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, n := range []int{10, 2048, 2049, 5000, 20000, 28000, ShortMaxBytes} {
		text := strings.ToValidUTF8(randomText(r, n), "")
		for !FitsShort(text) { // rune boundaries can need a 17th chunk
			text = text[:len(text)-1]
		}
		chunks, err := chunkText(text, 512, 448)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		want, err := runChunked(context.Background(), &hashBackend{}, chunks)
		if err != nil {
			t.Fatal(err)
		}
		got, err := runChunkedParallel(context.Background(), &hashBackend{}, chunks)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%d bytes: parallel scores differ from sequential", n)
		}
		if !reflect.DeepEqual(maxScore(got), maxScore(want)) {
			t.Fatalf("%d bytes: max differs", n)
		}
	}
}

func TestShortPathScoresRepeatedChunksOnce(t *testing.T) {
	b := &hashBackend{}
	text := strings.Repeat(strings.Repeat("x", 1792), 8) // 7 identical chunks and a shorter last one
	r := NewRunnerWith(b)
	if _, err := r.Scan(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	chunks, _ := chunkText(text, 512, 448)
	distinct := map[string]bool{}
	for _, c := range chunks {
		distinct[c] = true
	}
	if got := int(b.calls.Load()); got != len(distinct) || len(distinct) >= len(chunks) {
		t.Fatalf("%d runs for %d chunks (%d distinct)", got, len(chunks), len(distinct))
	}
}

func TestFitsShortMatchesChunkText(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, n := range []int{0, 2048, 2049, ShortMaxBytes - 3, ShortMaxBytes - 1, ShortMaxBytes, ShortMaxBytes + 1, 40000} {
		for _, text := range []string{strings.Repeat("a", n), strings.ToValidUTF8(randomText(r, n), ""), strings.Repeat("ế", n/3)} {
			_, err := chunkText(text, 512, 448)
			if fits := FitsShort(text); fits != (err == nil) {
				t.Fatalf("%d bytes: FitsShort = %v, chunkText err = %v", len(text), fits, err)
			}
		}
	}
}

func TestScanLongNeedsALongScan(t *testing.T) {
	r := NewRunnerWith(&heuristicInjectionBackend{})
	text := strings.Repeat("benign padding text. ", 20000) + payload // about 420 KB
	if _, err := r.Scan(context.Background(), text); !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("without a LongScan: err = %v", err)
	}
	ls := NewLongScan(LongOptions{})
	s, err := r.Scan(WithLongScan(context.Background(), ls), text)
	if err != nil {
		t.Fatal(err)
	}
	if s.Injection.Confidence < 0.85 || s.EarlyExit {
		t.Fatalf("payload at the end of a long text: %+v", s.Injection)
	}
	st := ls.Stats()
	if st.Windows < 200 || st.Scored+st.Skipped+st.Duplicates != st.Windows || st.Skipped != 0 {
		t.Fatalf("stats %+v", st)
	}
	// Texts that fit the short path never take the long path.
	short := strings.Repeat("a", 1000) + " " + payload
	if _, err := r.Scan(WithLongScan(context.Background(), ls), short); err != nil {
		t.Fatal(err)
	}
	if ls.Stats() != st {
		t.Fatal("a short text went to the long path")
	}
}

func TestScanLongBudget(t *testing.T) {
	r := NewRunnerWith(&hashBackend{})
	text := strings.Repeat("y", 40000)
	ls := NewLongScan(LongOptions{MaxTokens: 15000})
	ctx := WithLongScan(context.Background(), ls)
	if _, err := r.Scan(ctx, text); err != nil { // 10000 tokens
		t.Fatal(err)
	}
	if _, err := r.Scan(ctx, text+"z"); !errors.Is(err, ErrInputTooLong) { // 10001 more
		t.Fatalf("over the budget: err = %v", err)
	}
}

func TestScoreLongChunksEarlyExitAndDedupe(t *testing.T) {
	b := &hashBackend{}
	pad := strings.Repeat("p", 1792)
	attack := strings.Repeat(pad, 3) + payload + strings.Repeat(pad, 40)
	clean := strings.Repeat(pad, 30) + "q"
	in := []LongInput{{Text: attack, Threshold: 0.9}, {Text: clean, Threshold: 0.9}, {Text: clean}}
	lim := testLimiter{make(chan struct{}, 1)} // one worker: chunks run in order
	res, st, err := ScoreLongChunks(context.Background(), func(ctx context.Context, t string) (Score, error) {
		s, err := b.Run(ctx, t)
		return s[0], err
	}, in, LongOptions{Limiter: lim})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Score.Confidence != 0.99 || !res[0].EarlyExit {
		t.Fatalf("attack: %+v", res[0])
	}
	if res[1].EarlyExit || res[2].EarlyExit || !reflect.DeepEqual(res[1], res[2]) {
		t.Fatalf("clean texts: %+v / %+v", res[1], res[2])
	}
	if st.Skipped == 0 || st.Duplicates == 0 {
		t.Fatalf("stats %+v", st)
	}
	for c, n := range b.seen {
		if n != 1 {
			t.Fatalf("chunk %.10q scored %d times", c, n)
		}
	}
	// Every chunk of a text that is not decided is scored.
	for _, c := range chunkAll(clean, shortWindowChars, shortStrideChars) {
		if b.seen[c] != 1 {
			t.Fatal("a chunk of the clean text was not scored")
		}
	}
}

func TestRunLongBatchesStopsOnError(t *testing.T) {
	boom := errors.New("boom")
	var ran atomic.Int32
	_, err := RunLongBatches(context.Background(), 2, [][]int{{0}, {0}, {0}, {0}}, []float64{0},
		[][]int{{0}, {1}, {2}, {3}}, func(context.Context, []int) ([]float64, error) {
			ran.Add(1)
			return nil, boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunLongBatches(ctx, 1, [][]int{{0}}, []float64{0}, [][]int{{0}},
		func(context.Context, []int) ([]float64, error) { return []float64{0}, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: err = %v", err)
	}
}

// The fused backend leaves L3 out on the long path.
func TestFusedLongPathLeavesOutL3(t *testing.T) {
	f := fusion.New()
	l3 := &countLayer{}
	f.Set(fusion.L3, l3, fusion.Identity)
	r := NewRunnerWith(FusedBackend{F: f})
	text := strings.Repeat("harmless words here. ", 3000)
	if _, err := r.Scan(WithLongScan(context.Background(), NewLongScan(LongOptions{})), text); err != nil {
		t.Fatal(err)
	}
	if l3.n.Load() != 0 {
		t.Fatalf("L3 ran %d times on the long path", l3.n.Load())
	}
	if _, err := r.Scan(context.Background(), text[:5000]); err != nil {
		t.Fatal(err)
	}
	if l3.n.Load() == 0 {
		t.Fatal("L3 did not run on the short path")
	}
}

type countLayer struct{ n atomic.Int32 }

func (c *countLayer) Score(context.Context, string) (fusion.LayerResult, error) {
	c.n.Add(1)
	return fusion.LayerResult{Score: 0.1}, nil
}

type testLimiter struct{ c chan struct{} }

func (l testLimiter) Acquire(ctx context.Context) error {
	select {
	case l.c <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l testLimiter) Release() { <-l.c }
func (l testLimiter) Cap() int { return cap(l.c) }
