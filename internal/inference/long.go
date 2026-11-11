// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"context"
	"fmt"
	"sync"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// The long path scores texts past the short path's limit (16 chunks of about
// 2 KB, see Scan): only when the operator raised MAX_SCAN_TOKENS, and only
// inside the gateway's large-input lane. Inputs that fit the short path never
// take it, so their scores do not change.
//
// With the classifier installed (ml.Live) a long text is tokenized once and
// cut into the classifier's token windows (256 tokens overlapping by 64);
// each window is fused from L1 on its text and L2 on its tokens, L3 left out,
// and the text's score is the largest window score. Without it, the text is
// cut into the short path's chunks, with no cap, and each chunk is scored
// without L3. Every window is scored unless its text is already decided: a
// window at or above the text's Threshold refuses the request whatever the
// other windows score, so they are skipped (early exit).

// Limiter bounds concurrent model runs (*onnx.Limiter).
type Limiter interface {
	Acquire(ctx context.Context) error
	Release()
	Cap() int
}

// LongInput is one text for the long path.
type LongInput struct {
	Text string
	// Threshold stops scoring the text once a window's score reaches it:
	// the request is refused anyway. 0 scores every window. Callers set it
	// only when reaching it blocks the request (not in redact mode).
	Threshold float64
	// Uncounted leaves the text's tokens out of MaxTokens: earlier turns,
	// which have a byte limit of their own.
	Uncounted bool
	// Adjust, when set, changes each window's (or chunk's) score for this
	// text, given the window's text, as ScanAdjusted does per chunk on the
	// short path. Threshold (early exit) and the text's score use the
	// adjusted scores. A window shared with a text without Adjust keeps its
	// own score there.
	Adjust ChunkAdjust
}

// adjusted is s as text x sees a unit with the given text.
func (x LongInput) adjusted(unit string, s Score) Score { return x.Adjust.Apply(unit, s) }

// LongOptions tune the long path.
type LongOptions struct {
	// Limiter bounds the model runs (the large-input lane's own limiter)
	// and how many batches run at once; nil: one at a time, unbounded.
	Limiter Limiter
	// BatchSize is the number of windows per model run (default 16).
	BatchSize int
	// MaxTokens refuses the texts with ErrInputTooLong when they hold more
	// tokens together, before any model runs; 0: no cap; negative: no
	// token left (any counted token refuses).
	MaxTokens int
	// KeepWindows returns every window's score in LongResult.Windows
	// (cmd/benchlong); the gateway leaves it off.
	KeepWindows bool
	// LongDoc is the long document rule (nil: none): a text's score is its
	// largest window after the rule, given the text's number of windows.
	LongDoc LongDocRule
}

// ruled is s under the long document rule for a text of n units (s without one).
func (o LongOptions) ruled(n int, s Score) Score {
	if o.LongDoc == nil {
		return s
	}
	return o.LongDoc.Apply(n, s)
}

// LongDocRule is a document-level decision of the long path: it maps a
// window's score (after LongInput.Adjust) to the score that counts for a text
// of n windows. Early exit and the text's score use the mapped scores, so a
// text is still decided by its strongest window. ml.LongDocRule implements it
// from the classifier's calibration.
type LongDocRule interface {
	Apply(n int, s Score) Score
}

// DefaultLongBatch is the default LongOptions.BatchSize.
const DefaultLongBatch = 16

// LongStats counts the work of a long scan.
type LongStats struct {
	Tokens     int // content tokens of the texts
	Counted    int // of those, the tokens MaxTokens counts (not Uncounted)
	Windows    int // windows of the texts
	Scored     int // windows fused
	Duplicates int // windows not scored again: an identical one was
	Skipped    int // windows not scored: their text was already decided
}

// Add sums two LongStats.
func (s LongStats) Add(o LongStats) LongStats {
	return LongStats{Tokens: s.Tokens + o.Tokens, Counted: s.Counted + o.Counted, Windows: s.Windows + o.Windows,
		Scored: s.Scored + o.Scored, Duplicates: s.Duplicates + o.Duplicates, Skipped: s.Skipped + o.Skipped}
}

// Count adds a text's tokens and reports whether MaxTokens still holds.
func (s *LongStats) Count(x LongInput, tokens int, o LongOptions) bool {
	s.Tokens += tokens
	if !x.Uncounted {
		s.Counted += tokens
	}
	return o.MaxTokens == 0 || s.Counted <= max(o.MaxTokens, 0)
}

// LongResult is the long path's verdict on one text.
type LongResult struct {
	Score Score
	// EarlyExit: some windows were skipped because the score reached the
	// threshold. The score is then a lower bound, not to be cached.
	EarlyExit bool
	// Windows are the text's windows (or chunks) in order, with LongOptions.KeepWindows
	// only; a skipped window has Skipped set and no score.
	Windows []LongWindow
}

// LongWindow is one window (or chunk) of a long text: its byte span and its
// score as the text sees it (after LongInput.Adjust, before the long
// document rule).
type LongWindow struct {
	Start, End int
	Score      Score
	Skipped    bool
}

// LongDetector is a Scorer with a long path of its own (ml.Live).
type LongDetector interface {
	ScoreLong(ctx context.Context, in []LongInput, o LongOptions) ([]LongResult, LongStats, error)
	// CountTokens is the number of tokens MAX_SCAN_TOKENS counts for text.
	CountTokens(text string) (int, error)
}

// EstimateTokens is the token count used without a tokenizer: 4 bytes per
// token, as for request.tokens in policies and the short path's chunks.
func EstimateTokens(text string) int { return (len(text) + 3) / 4 }

// FusedScore is the injection Score of a fused result.
func FusedScore(r fusion.Result) Score {
	label := "BENIGN"
	if r.Category != "" {
		label = r.Category
	}
	return Score{
		Label:      label,
		Confidence: float32(r.Score),
		Detail: &Detail{
			L1: r.Layers[fusion.L1], L2: r.Layers[fusion.L2], L3: r.Layers[fusion.L3],
			Category: r.Category, Categories: r.Categories, Rules: r.Rules, Floor: r.Floor,
		},
	}
}

// RunLongBatches runs the batches of a long scan on up to workers goroutines,
// in order. A unit (a window or a chunk) belongs to one or more texts
// (owners[unit]); thresholds[text] > 0 decides a text once one of its units
// scores at least that much. Before a batch runs, its units whose texts are
// all decided are dropped (early exit). run scores the units of a batch and
// returns their scores in order; it bounds its own model runs. RunLongBatches
// returns which units were scored, or the first error, which stops the rest.
func RunLongBatches(ctx context.Context, workers int, owners [][]int, thresholds []float64, batches [][]int,
	run func(ctx context.Context, units []int) ([]float64, error)) ([]bool, error) {
	return RunLongBatchesOwned(ctx, workers, owners, thresholds, batches, run, nil)
}

// RunLongBatchesOwned is RunLongBatches where a unit's score can differ by
// text: ownerScore(unit, text, score) is the score the threshold of text
// compares (nil: score for every text). It is called after run returned the
// unit's batch.
func RunLongBatchesOwned(ctx context.Context, workers int, owners [][]int, thresholds []float64, batches [][]int,
	run func(ctx context.Context, units []int) ([]float64, error),
	ownerScore func(unit, text int, score float64) float64) ([]bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		decided  = make([]bool, len(thresholds))
		scored   = make([]bool, len(owners))
		firstErr error
	)
	open := func(units []int) []int {
		mu.Lock()
		defer mu.Unlock()
		var out []int
		for _, u := range units {
			for _, t := range owners[u] {
				if !decided[t] {
					out = append(out, u)
					break
				}
			}
		}
		return out
	}
	settle := func(units []int, scores []float64) {
		mu.Lock()
		defer mu.Unlock()
		for i, u := range units {
			scored[u] = true
			for _, t := range owners[u] {
				s := scores[i]
				if ownerScore != nil {
					s = ownerScore(u, t, s)
				}
				if th := thresholds[t]; th > 0 && s >= th {
					decided[t] = true
				}
			}
		}
	}
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	jobs := make(chan []int)
	var wg sync.WaitGroup
	for range min(max(1, workers), max(1, len(batches))) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				units := open(b)
				if len(units) == 0 || ctx.Err() != nil {
					continue
				}
				scores, err := run(ctx, units)
				if err == nil && len(scores) != len(units) {
					err = fmt.Errorf("inference: %d scores for %d windows", len(scores), len(units))
				}
				if err != nil {
					fail(err)
					continue
				}
				settle(units, scores)
			}
		}()
	}
feed:
	for _, b := range batches {
		select {
		case jobs <- b:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return scored, nil
}

// ScoreLongChunks is the long path without token windows: each text is cut
// into the short path's chunks, with no cap, and score runs on each distinct
// chunk, at most Limiter.Cap() at a time. score's own model runs take their
// slots from the limiter the caller put in ctx (onnx.WithLimiter): taking one
// here too would nest them. Tokens are estimated (4 bytes each).
func ScoreLongChunks(ctx context.Context, score func(ctx context.Context, text string) (Score, error),
	in []LongInput, o LongOptions) ([]LongResult, LongStats, error) {
	var st LongStats
	var chunks []string
	var owners [][]int
	index := map[string]int{}
	units := make([][]int, len(in)) // per text, its chunks in order
	spans := make([][][2]int, len(in))
	thresholds := make([]float64, len(in))
	for i, x := range in {
		thresholds[i] = x.Threshold
		if !st.Count(x, EstimateTokens(x.Text), o) {
			return nil, st, ErrInputTooLong
		}
		for _, sp := range chunkSpansAll(x.Text, shortWindowChars, shortStrideChars) {
			c := x.Text[sp[0]:sp[1]]
			spans[i] = append(spans[i], sp)
			st.Windows++
			u, ok := index[c]
			if ok {
				st.Duplicates++
			} else {
				u = len(chunks)
				index[c] = u
				chunks = append(chunks, c)
				owners = append(owners, nil)
			}
			if n := len(owners[u]); n == 0 || owners[u][n-1] != i {
				owners[u] = append(owners[u], i)
			}
			units[i] = append(units[i], u)
		}
	}
	batches := make([][]int, len(chunks))
	for u := range chunks {
		batches[u] = []int{u}
	}
	res := make([]Score, len(chunks))
	workers := 1
	if o.Limiter != nil {
		workers = o.Limiter.Cap()
	}
	scored, err := RunLongBatchesOwned(ctx, workers, owners, thresholds, batches,
		func(ctx context.Context, us []int) ([]float64, error) {
			out := make([]float64, len(us))
			for i, u := range us {
				s, err := score(ctx, chunks[u])
				if err != nil {
					return nil, err
				}
				res[u] = s
				out[i] = float64(s.Confidence)
			}
			return out, nil
		}, func(u, t int, s float64) float64 {
			if in[t].Adjust == nil && o.LongDoc == nil {
				return s
			}
			return float64(o.ruled(len(units[t]), in[t].adjusted(chunks[u], res[u])).Confidence)
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
	out := make([]LongResult, len(in))
	for i, us := range units {
		adj := func(u int) Score { return in[i].adjusted(chunks[u], res[u]) }
		out[i] = aggregateLong(us, scored, func(u int) Score { return o.ruled(len(us), adj(u)) })
		if o.KeepWindows {
			out[i].Windows = make([]LongWindow, len(us))
			for k, u := range us {
				w := LongWindow{Start: spans[i][k][0], End: spans[i][k][1], Skipped: !scored[u]}
				if scored[u] {
					w.Score = adj(u)
				}
				out[i].Windows[k] = w
			}
		}
	}
	return out, st, nil
}

// aggregateLong is a text's result from its units, in order: the highest
// score (the first of equal ones), and EarlyExit when a unit was skipped.
func aggregateLong(units []int, scored []bool, score func(int) Score) LongResult {
	var out LongResult
	first := true
	for _, u := range units {
		if !scored[u] {
			out.EarlyExit = true
			continue
		}
		if s := score(u); first || s.Confidence > out.Score.Confidence {
			out.Score, first = s, false
		}
	}
	return out
}

// chunkAll is chunkText without the cap.
func chunkAll(text string, winChars, strideChars int) []string {
	spans := chunkSpansAll(text, winChars, strideChars)
	chunks := make([]string, len(spans))
	for i, sp := range spans {
		chunks[i] = text[sp[0]:sp[1]]
	}
	return chunks
}

// chunkSpansAll are the byte spans [start,end) of chunkAll's chunks.
func chunkSpansAll(text string, winChars, strideChars int) [][2]int {
	if len(text) <= winChars {
		return [][2]int{{0, len(text)}}
	}
	var spans [][2]int
	for start := 0; ; start = runeStart(text, start+strideChars) {
		end := runeStart(text, min(start+winChars, len(text)))
		spans = append(spans, [2]int{start, end})
		if end == len(text) {
			return spans
		}
	}
}

// longKey carries a LongScan in a context.
type longKey struct{}

// LongScan lets Scan take the long path for texts past the short path's
// limit, within one request: the gateway makes one after the request was
// admitted to the large-input lane. Texts scored ahead with Prescore are
// served from it; others are scored when Scan meets them. MaxTokens in its
// options is the budget of the whole request.
type LongScan struct {
	opts LongOptions

	mu     sync.Mutex
	done   map[longDone]LongResult
	stats  LongStats
	budget int // tokens left; only with opts.MaxTokens > 0
}

// NewLongScan returns an empty LongScan.
func NewLongScan(o LongOptions) *LongScan {
	return &LongScan{opts: o, done: map[longDone]LongResult{}, budget: o.MaxTokens}
}

// longDone keys a LongScan's results: the same text scored with and without
// an Adjust has two results.
type longDone struct {
	text     string
	adjusted bool
}

func doneKey(x LongInput) longDone { return longDone{x.Text, x.Adjust != nil} }

// WithLongScan returns ctx carrying ls.
func WithLongScan(ctx context.Context, ls *LongScan) context.Context {
	return context.WithValue(ctx, longKey{}, ls)
}

func longScanFrom(ctx context.Context) *LongScan {
	ls, _ := ctx.Value(longKey{}).(*LongScan)
	return ls
}

// Stats is the work done so far.
func (ls *LongScan) Stats() LongStats {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.stats
}

// Prescore scores texts on the long path together, so their windows share
// batches and duplicates are scored once; Scan then finds them.
func (r *Runner) Prescore(ctx context.Context, ls *LongScan, in []LongInput) error {
	// Copies of a text stay in: their windows are scored once and counted
	// as duplicates.
	var todo []LongInput
	ls.mu.Lock()
	for _, x := range in {
		if _, ok := ls.done[doneKey(x)]; !ok {
			todo = append(todo, x)
		}
	}
	ls.mu.Unlock()
	if len(todo) == 0 {
		return nil
	}
	_, err := r.scanLong(ctx, ls, todo)
	return err
}

// scanLong scores texts within ls's budget and keeps the results.
func (r *Runner) scanLong(ctx context.Context, ls *LongScan, in []LongInput) ([]LongResult, error) {
	o := ls.opts
	ls.mu.Lock()
	if o.MaxTokens > 0 {
		o.MaxTokens = ls.budget
		if o.MaxTokens == 0 {
			o.MaxTokens = -1 // spent: any counted token refuses
		}
	}
	ls.mu.Unlock()
	res, st, err := r.ScanLong(ctx, in, o)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.stats = ls.stats.Add(st)
	if err != nil {
		return nil, err
	}
	ls.budget -= st.Counted
	for i, x := range in {
		ls.done[doneKey(x)] = res[i]
	}
	return res, nil
}

// lookup returns the result of a text scored on the long path before, with
// or without an Adjust.
func (ls *LongScan) lookup(x LongInput) (LongResult, bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	r, ok := ls.done[doneKey(x)]
	return r, ok
}

// longBackend is a ModelBackend with a long path of its own.
type longBackend interface {
	scoreLong(ctx context.Context, in []LongInput, o LongOptions) ([]LongResult, LongStats, error)
	countTokens(text string) (int, error)
}

// ScanLong scores texts on the long path (see the comment at the top of this
// file) with the injection backend.
func (r *Runner) ScanLong(ctx context.Context, in []LongInput, o LongOptions) ([]LongResult, LongStats, error) {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultLongBatch
	}
	if lb, ok := r.injection.(longBackend); ok {
		return lb.scoreLong(ctx, in, o)
	}
	return ScoreLongChunks(ctx, func(ctx context.Context, text string) (Score, error) {
		s, err := r.injection.Run(ctx, text)
		if err != nil {
			return Score{}, err
		}
		return maxScore(s), nil
	}, in, o)
}

// CountTokens is the number of tokens MAX_SCAN_TOKENS counts for text: the
// classifier's tokens when it is installed, else EstimateTokens.
func (r *Runner) CountTokens(text string) (int, error) {
	if lb, ok := r.injection.(longBackend); ok {
		return lb.countTokens(text)
	}
	return EstimateTokens(text), nil
}

func (b FusedBackend) scoreLong(ctx context.Context, in []LongInput, o LongOptions) ([]LongResult, LongStats, error) {
	if d, ok := b.F.(LongDetector); ok {
		return d.ScoreLong(ctx, in, o)
	}
	score := func(ctx context.Context, text string) (Score, error) {
		return FusedScore(b.F.Score(ctx, text)), nil
	}
	if w, ok := b.F.(interface {
		ScoreWithout(ctx context.Context, text string, slot int) fusion.Result
	}); ok {
		score = func(ctx context.Context, text string) (Score, error) {
			return FusedScore(w.ScoreWithout(ctx, text, fusion.L3)), nil
		}
	}
	return ScoreLongChunks(ctx, score, in, o)
}

func (b FusedBackend) countTokens(text string) (int, error) {
	if d, ok := b.F.(LongDetector); ok {
		return d.CountTokens(text)
	}
	return EstimateTokens(text), nil
}
