package onnx

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTokenizer maps each whitespace-separated word to its length as id.
type fakeTokenizer struct{ closed atomic.Bool }

func (f *fakeTokenizer) Encode(text string) ([]int64, error) {
	var ids []int64
	for _, w := range strings.Fields(text) {
		ids = append(ids, int64(len(w))+10)
	}
	return ids, nil
}
func (f *fakeTokenizer) Specials() ([]int64, []int64) { return []int64{1}, []int64{2} }
func (f *fakeTokenizer) Close() error                 { f.closed.Store(true); return nil }

// fakeSession returns, for a classifier, logits [0, x] where x is 10 if the
// row contains id 99 ("bad" word of length 89) else -10; for an embedder, the
// hidden state of a token is [id, 1].
type fakeSession struct {
	embed   bool
	mu      sync.Mutex
	batches [][2]int // batch, seq
	active  atomic.Int32
	peak    atomic.Int32
	delay   time.Duration
	closed  atomic.Bool
}

func (f *fakeSession) Run(ctx context.Context, ids, mask, _ []int64, batch, seq int) ([]float32, []int64, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	f.mu.Lock()
	f.batches = append(f.batches, [2]int{batch, seq})
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if f.embed {
		out := make([]float32, batch*seq*2)
		for i := range ids {
			out[2*i] = float32(ids[i])
			out[2*i+1] = 1
		}
		return out, []int64{int64(batch), int64(seq), 2}, nil
	}
	out := make([]float32, batch*2)
	for r := 0; r < batch; r++ {
		out[2*r+1] = -10
		for j := 0; j < seq; j++ {
			if ids[r*seq+j] == 99 && mask[r*seq+j] == 1 {
				out[2*r+1] = 10
			}
		}
	}
	return out, []int64{int64(batch), 2}, nil
}
func (f *fakeSession) Close() error { f.closed.Store(true); return nil }

func newFakeClassifier(t *testing.T, o Options) (*Classifier, *fakeSession, *fakeTokenizer) {
	t.Helper()
	tok, sess := &fakeTokenizer{}, &fakeSession{}
	if o.Limiter == nil {
		o.Limiter = NewLimiter(4)
	}
	m, err := newModel(tok, sess, modelConfig{}, o)
	if err != nil {
		t.Fatal(err)
	}
	return &Classifier{m: m, labels: []string{"SAFE", "INJECTION"}}, sess, tok
}

func words(n int) string { return strings.TrimSpace(strings.Repeat("abc ", n)) }

var bad = strings.Repeat("x", 89) // encodes to id 99

func TestChunkWindows(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{MaxLength: 6, Stride: 1, MaxChunks: -1})
	ids := []int64{11, 12, 13, 14, 15, 16, 17, 18, 19}
	got, err := c.m.chunk(ids)
	if err != nil {
		t.Fatal(err)
	}
	// window 4 content tokens, step 3
	want := [][]int64{{1, 11, 12, 13, 14, 2}, {1, 14, 15, 16, 17, 2}, {1, 17, 18, 19, 2}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("window %d: got %v want %v", i, got[i], want[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("window %d: got %v want %v", i, got[i], want[i])
			}
		}
	}
	empty, _ := c.m.chunk(nil)
	if len(empty) != 1 || len(empty[0]) != 2 {
		t.Fatalf("empty text: %v", empty)
	}
	exact, _ := c.m.chunk(ids[:4])
	if len(exact) != 1 {
		t.Fatalf("exact fit should be one window: %v", exact)
	}
}

func TestChunkCap(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{MaxLength: 6, Stride: 1, MaxChunks: 2})
	if _, err := c.m.chunk(make([]int64, 20)); !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("want ErrInputTooLong, got %v", err)
	}
	if _, err := c.Score(context.Background(), []string{words(50)}); !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("Score: want ErrInputTooLong, got %v", err)
	}
}

func TestOptionsValidation(t *testing.T) {
	if _, err := newModel(&fakeTokenizer{}, &fakeSession{}, modelConfig{}, Options{MaxLength: 2}); err == nil {
		t.Fatal("MaxLength 2 leaves no content room; want error")
	}
	if _, err := newModel(&fakeTokenizer{}, &fakeSession{}, modelConfig{}, Options{MaxLength: 10, Stride: 8}); err == nil {
		t.Fatal("stride >= window; want error")
	}
	m, err := newModel(&fakeTokenizer{}, &fakeSession{}, modelConfig{MaxPositionEmbeddings: 128}, Options{})
	if err != nil || m.maxLen != 128 || m.batchSize != defaultBatchSize || m.stride != defaultStride {
		t.Fatalf("defaults: %+v %v", m, err)
	}
}

func TestScoreFindsPayloadInLaterWindowAndBatches(t *testing.T) {
	c, sess, _ := newFakeClassifier(t, Options{MaxLength: 10, Stride: 2, BatchSize: 3, MaxChunks: -1})
	texts := []string{
		"hello there",                          // benign, 1 window
		words(40) + " " + bad,                  // payload hidden after padding
		words(5) + " " + bad + " " + words(30), // payload early
		"",
	}
	got, err := c.Score(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	inj := c.LabelIndex("INJECTION")
	for i, want := range []bool{false, true, true, false} {
		if (got[i][inj] > 0.5) != want {
			t.Errorf("text %d: INJECTION=%v, want high=%v", i, got[i][inj], want)
		}
	}
	if s := got[0][0] + got[0][1]; math.Abs(float64(s)-1) > 1e-5 {
		t.Errorf("single-window probabilities should sum to 1, got %v", s)
	}
	for _, b := range sess.batches {
		if b[0] > 3 || b[1] > 10 {
			t.Errorf("batch %v exceeds BatchSize 3 / MaxLength 10", b)
		}
	}
	if len(sess.batches) < 2 {
		t.Errorf("expected several batches, got %v", sess.batches)
	}
}

func TestEmbedMeanPoolL2(t *testing.T) {
	tok, sess := &fakeTokenizer{}, &fakeSession{embed: true}
	m, err := newModel(tok, sess, modelConfig{}, Options{MaxLength: 8, Stride: 1, Limiter: NewLimiter(1), MaxChunks: -1})
	if err != nil {
		t.Fatal(err)
	}
	e := &Embedder{m: m}
	// "a bb" → ids [1, 11, 12, 2] (with specials); padded rows must not count.
	got, err := e.Embed(context.Background(), []string{"a bb", words(3) + " " + words(20)})
	if err != nil {
		t.Fatal(err)
	}
	mean := (1.0 + 11 + 12 + 2) / 4
	norm := math.Sqrt(mean*mean + 1)
	if math.Abs(float64(got[0][0])-mean/norm) > 1e-5 || math.Abs(float64(got[0][1])-1/norm) > 1e-5 {
		t.Errorf("embedding %v, want [%v %v]", got[0], mean/norm, 1/norm)
	}
	for i, v := range got {
		var n float64
		for _, x := range v {
			n += float64(x) * float64(x)
		}
		if math.Abs(n-1) > 1e-5 {
			t.Errorf("vector %d not unit length: %v", i, n)
		}
	}
}

func TestLimiterBoundsConcurrency(t *testing.T) {
	lim := NewLimiter(2)
	c, sess, _ := newFakeClassifier(t, Options{Limiter: lim, BatchSize: 1})
	sess.delay = 5 * time.Millisecond
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Score(context.Background(), []string{"a b", "c d"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if p := sess.peak.Load(); p > 2 || p < 1 {
		t.Fatalf("peak concurrency %d, limiter is 2", p)
	}
}

func TestContextCancellation(t *testing.T) {
	lim := NewLimiter(1)
	c, sess, _ := newFakeClassifier(t, Options{Limiter: lim})
	sess.delay = time.Second

	if err := lim.Acquire(context.Background()); err != nil { // hold the only slot
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Score(ctx, []string{"x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting on the limiter: want deadline, got %v", err)
	}
	lim.Release()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if _, err := c.Score(ctx2, []string{"x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("during the run: want deadline, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("run was not interrupted")
	}
}

func TestCloseWaitsAndRejects(t *testing.T) {
	c, sess, tok := newFakeClassifier(t, Options{})
	sess.delay = 30 * time.Millisecond
	done := make(chan error)
	go func() { _, err := c.Score(context.Background(), []string{"a"}); done <- err }()
	time.Sleep(5 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("in-flight call should finish: %v", err)
	}
	if !sess.closed.Load() || !tok.closed.Load() {
		t.Fatal("resources not closed")
	}
	if _, err := c.Score(context.Background(), []string{"a"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if _, err := c.TokenCount("a"); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal("second Close should be a no-op")
	}
}

func TestTokenCount(t *testing.T) {
	c, _, _ := newFakeClassifier(t, Options{})
	if n, err := c.TokenCount("one two three"); err != nil || n != 3 {
		t.Fatalf("got %d %v", n, err)
	}
}

func TestLabelsFromID2Label(t *testing.T) {
	got, err := labelsFromID2Label(map[string]string{"1": "INJECTION", "0": "SAFE"})
	if err != nil || len(got) != 2 || got[0] != "SAFE" || got[1] != "INJECTION" {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []map[string]string{nil, {"0": "A", "2": "B"}, {"x": "A"}} {
		if _, err := labelsFromID2Label(bad); err == nil {
			t.Errorf("%v: want error", bad)
		}
	}
}

func TestSoftmax(t *testing.T) {
	p := softmax([]float32{1000, 1000})
	if math.Abs(float64(p[0])-0.5) > 1e-6 {
		t.Fatalf("unstable softmax: %v", p)
	}
}

func TestMaxConcurrencyFromEnv(t *testing.T) {
	t.Setenv(EnvMaxConcurrency, "3")
	if MaxConcurrencyFromEnv() != 3 {
		t.Fatal("env not read")
	}
	t.Setenv(EnvMaxConcurrency, "nope")
	if MaxConcurrencyFromEnv() < 1 {
		t.Fatal("fallback should be NumCPU")
	}
}
