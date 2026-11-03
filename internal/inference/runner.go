// Package inference wraps ONNX Runtime (via hugot) for in-process ML inference.
//
// Design: 4 models loaded once at startup, evaluated concurrently per request
// using errgroup fan-out. Max latency = slowest model (~15ms), not sum.
//
// IMPORTANT: Do not use DeBERTa-v3-base on CPU hot path (~1714ms).
// Use DeBERTa-v3-xsmall or DistilBERT-class models only.
//
// Chunking is required: naive truncation at 512 tokens is a security bug
// (attacker prepends 512 benign tokens to hide injection payload).
package inference

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"

	"github.com/promptshield/promptshield/internal/inference/fusion"
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
	Injection  Score
	PII        []PIIEntity
	Toxicity   Score
	Topic      []Score
}

// PIIEntity is a detected PII span.
type PIIEntity struct {
	Type  string  // SSN, CREDIT_CARD, EMAIL, PHONE, etc.
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
	// TODO: load models via hugot (requires ORT shared lib on Linux)
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

// Scan runs all 4 models concurrently and returns aggregated scores.
// Chunking with sliding window is applied before each model call.
func (r *Runner) Scan(ctx context.Context, text string) (Scores, error) {
	chunks, err := chunkText(text, 512, 448)
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
		scores, err := runChunked(gctx, r.injection, chunks)
		if err != nil {
			return fmt.Errorf("injection model: %w", err)
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
		Injection: maxScore(injScores),  // max(), not mean() — attacker hides in tail
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
