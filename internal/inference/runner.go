// Package inference runs the injection detector over a request's text.
//
// The injection backend is the fusion of L1 rules and, when their models are
// installed, the L2 classifier and L3 embeddings (packages fusion and ml; the
// ONNX models run in-process through package onnx). The PII, toxicity and
// topic slots hold stubs that always return a neutral score: no such
// detector exists yet.
//
// Chunking is required: naive truncation is a security bug (an attacker
// prepends benign text to push the payload past the cut). Text is split into
// overlapping windows and the worst window counts.
package inference

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// ErrInputTooLong means the text needs more windows than we are willing to scan.
// Callers must reject the request: skipping the tail would let padding hide a payload.
var ErrInputTooLong = errors.New("input too long to scan")

// Score is the result from a single model.
type Score struct {
	Label      string
	Confidence float32
	Detail     *Detail // fused injection detail; nil for other backends
}

// Scores holds all model outputs for a single request.
type Scores struct {
	Injection Score
	PII       []PIIEntity
	Toxicity  Score
	Topic     []Score
	// EarlyExit is set by the long path when it stopped scoring the text
	// once a window reached the refusal threshold: Injection is then a lower
	// bound and must not be cached.
	EarlyExit bool `json:",omitempty"`
}

// PIIEntity is a detected PII span.
type PIIEntity struct {
	Type  string // SSN, CREDIT_CARD, EMAIL, PHONE, etc.
	Start int
	End   int
	Score float32
}

// Runner holds loaded ONNX models and runs concurrent inference.
type Runner struct {
	injection ModelBackend
	pii       ModelBackend
	toxicity  ModelBackend
	topic     ModelBackend
}

// ModelBackend is the interface each ONNX model implements.
type ModelBackend interface {
	Run(ctx context.Context, text string) ([]Score, error)
}

// NewRunner loads models from the given directory.
func NewRunner(modelsDir string) (*Runner, error) {
	// Injection: fusion over the L1 v2 rules (L2/L3 plug into the Fuser).
	// The legacy regex detector stays available through NewRegexRunner.
	return &Runner{
		injection: FusedBackend{F: fusion.New()},
		pii:       &stubBackend{label: "O", score: 0.0},
		toxicity:  &stubBackend{label: "non-toxic", score: 0.0},
		topic:     &stubBackend{label: "unknown", score: 0.0},
	}, nil
}

// NewRunnerWith builds a Runner around an injection backend.
func NewRunnerWith(injection ModelBackend) *Runner {
	return &Runner{
		injection: injection,
		pii:       &stubBackend{label: "O", score: 0.0},
		toxicity:  &stubBackend{label: "non-toxic", score: 0.0},
		topic:     &stubBackend{label: "unknown", score: 0.0},
	}
}

// The short path's chunks: about 512 tokens (4 bytes each) overlapping by
// 64, at most 16 of them, so a text of up to ShortMaxBytes.
const (
	shortWindowChars = 512 * charsPerToken
	shortStrideChars = 448 * charsPerToken
	shortMaxChunks   = 16
	charsPerToken    = 4
	// ShortMaxBytes is the longest text the short path takes (a text a few
	// bytes shorter can still need a 17th chunk: cuts move back to a rune
	// boundary; FitsShort is exact).
	ShortMaxBytes = shortWindowChars + (shortMaxChunks-1)*shortStrideChars
)

// FitsShort reports whether Scan scores text on the short path, as every
// text was before the long path existed; a longer one needs the long path
// (LongScan) or is refused with ErrInputTooLong.
func FitsShort(text string) bool {
	if len(text) <= shortWindowChars {
		return true
	}
	if len(text) > ShortMaxBytes {
		return false
	}
	n := 0
	for start := 0; ; start = runeStart(text, start+shortStrideChars) {
		if n == shortMaxChunks {
			return false
		}
		n++
		if end := runeStart(text, min(start+shortWindowChars, len(text))); end == len(text) {
			return true
		}
	}
}

// shortParallel bounds the chunks of one text scored at once on the short
// path. Each chunk's model runs still take a slot of the model limiter
// (INFERENCE_MAX_CONCURRENCY), so this only keeps one request from taking
// every slot.
const shortParallel = 4

// Scan runs all 4 models concurrently and returns aggregated scores.
// Chunking with sliding window is applied before each model call.
//
// A text past the short path's limit (FitsShort) is refused with
// ErrInputTooLong, unless ctx carries a LongScan: then it takes the long path.
func (r *Runner) Scan(ctx context.Context, text string) (Scores, error) {
	return r.ScanAdjusted(ctx, text, nil)
}

// ChunkAdjust may change the injection score of one chunk (on the long path,
// one window) before the worst one is taken; chunk is the text the detector
// saw.
type ChunkAdjust func(chunk string, s Score) Score

// Apply is a(chunk, s), or s when a is nil.
func (a ChunkAdjust) Apply(chunk string, s Score) Score {
	if a == nil {
		return s
	}
	return a(chunk, s)
}

// ScanAdjusted is Scan with adjust applied to each chunk's injection score
// (nil: none), before the worst chunk is taken and, on the long path, before
// early exit compares it with the threshold.
func (r *Runner) ScanAdjusted(ctx context.Context, text string, adjust ChunkAdjust) (Scores, error) {
	chunks, err := chunkText(text, 512, 448)
	if errors.Is(err, ErrInputTooLong) {
		if ls := longScanFrom(ctx); ls != nil {
			return r.scanLongText(ctx, ls, LongInput{Text: text, Adjust: adjust})
		}
	}
	if err != nil {
		return Scores{}, err
	}

	var (
		injScores []Score
		toxScores []Score
		topScores []Score
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		scores, err := runChunkedParallel(gctx, r.injection, chunks)
		if err != nil {
			return fmt.Errorf("injection model: %w", err)
		}
		if adjust != nil {
			scores = adjustChunks(chunks, scores, adjust)
		}
		injScores = scores
		return nil
	})

	g.Go(func() error {
		scores, err := runChunked(gctx, r.toxicity, chunks)
		if err != nil {
			return fmt.Errorf("toxicity model: %w", err)
		}
		toxScores = scores
		return nil
	})

	g.Go(func() error {
		scores, err := runChunked(gctx, r.topic, chunks)
		if err != nil {
			return fmt.Errorf("topic model: %w", err)
		}
		topScores = scores
		return nil
	})

	if err := g.Wait(); err != nil {
		return Scores{}, err
	}

	return Scores{
		Injection: maxScore(injScores), // max(), not mean() — attacker hides in tail
		Toxicity:  maxScore(toxScores),
		Topic:     topScores,
	}, nil
}

// chunkText splits text into overlapping windows for safe classification.
// window=512 tokens, stride=448 (64-token overlap). Refuses text that needs more
// than 16 chunks to prevent CPU exhaustion DoS.
func chunkText(text string, windowSize, stride int) ([]string, error) {
	// TODO: use daulet/tokenizers (cgo) for proper tokenization
	// For now: character-based approximation (1 token ~= 4 chars)
	const charsPerToken = 4
	const maxChunks = 16
	winChars := windowSize * charsPerToken
	strideChars := stride * charsPerToken

	if len(text) <= winChars {
		return []string{text}, nil
	}

	var chunks []string
	for start := 0; ; start = runeStart(text, start+strideChars) {
		if len(chunks) == maxChunks {
			return nil, ErrInputTooLong
		}
		end := runeStart(text, min(start+winChars, len(text)))
		chunks = append(chunks, text[start:end])
		if end == len(text) {
			return chunks, nil
		}
	}
}

// runeStart moves i back to the nearest rune boundary.
func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// runChunkedParallel is runChunked with up to shortParallel chunks at a time
// and each distinct chunk run once. Each chunk is scored on its own exactly as
// runChunked does, and the scores come back in chunk order, so the result is
// the same.
func runChunkedParallel(ctx context.Context, m ModelBackend, chunks []string) ([]Score, error) {
	if len(chunks) == 1 {
		return runChunked(ctx, m, chunks)
	}
	first := make(map[string]int, len(chunks)) // chunk text -> first index
	var uniq []int
	for i, c := range chunks {
		if _, ok := first[c]; !ok {
			first[c] = i
			uniq = append(uniq, i)
		}
	}
	per := make([][]Score, len(chunks))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(shortParallel)
	for _, i := range uniq {
		g.Go(func() error {
			s, err := m.Run(gctx, chunks[i])
			per[i] = s
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var all []Score
	for _, c := range chunks {
		all = append(all, per[first[c]]...)
	}
	return all, nil
}

// adjustChunks applies adjust to the scores of runChunked(Parallel), in chunk
// order. A backend returns one injection score per chunk (FusedBackend, the
// regex detector); with any other count the scores are left alone.
func adjustChunks(chunks []string, scores []Score, adjust ChunkAdjust) []Score {
	if len(scores) != len(chunks) {
		return scores
	}
	out := make([]Score, len(scores))
	for i, s := range scores {
		out[i] = adjust(chunks[i], s)
	}
	return out
}

// scanLongText scores one text on the long path, or finds it scored there.
func (r *Runner) scanLongText(ctx context.Context, ls *LongScan, x LongInput) (Scores, error) {
	text := x.Text
	res, ok := ls.lookup(x)
	if !ok {
		out, err := r.scanLong(ctx, ls, []LongInput{x})
		if err != nil {
			return Scores{}, err
		}
		res = out[0]
	}
	// The other slots see every chunk, as on the short path.
	chunks := chunkAll(text, shortWindowChars, shortStrideChars)
	tox, err := runChunked(ctx, r.toxicity, chunks)
	if err != nil {
		return Scores{}, fmt.Errorf("toxicity model: %w", err)
	}
	top, err := runChunked(ctx, r.topic, chunks)
	if err != nil {
		return Scores{}, fmt.Errorf("topic model: %w", err)
	}
	return Scores{Injection: res.Score, Toxicity: maxScore(tox), Topic: top, EarlyExit: res.EarlyExit}, nil
}

func runChunked(ctx context.Context, m ModelBackend, chunks []string) ([]Score, error) {
	var all []Score
	for _, chunk := range chunks {
		scores, err := m.Run(ctx, chunk)
		if err != nil {
			return nil, err
		}
		all = append(all, scores...)
	}
	return all, nil
}

// maxScore returns the score with the highest confidence.
// Using max() (not mean()) because the injection payload could be in any chunk.
func maxScore(scores []Score) Score {
	if len(scores) == 0 {
		return Score{}
	}
	best := scores[0]
	for _, s := range scores[1:] {
		if s.Confidence > best.Confidence {
			best = s
		}
	}
	return best
}

// stubBackend is a no-op model for development without ORT.
type stubBackend struct {
	label string
	score float32
}

func (s *stubBackend) Run(_ context.Context, _ string) ([]Score, error) {
	return []Score{{Label: s.label, Confidence: s.score}}, nil
}
