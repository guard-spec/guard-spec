package evalset

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/promptshield/promptshield/internal/inference"
	"github.com/promptshield/promptshield/internal/inference/fusion"
	"github.com/promptshield/promptshield/internal/inference/rules"
	"github.com/promptshield/promptshield/internal/sanitizer"
)

// Detector scores sanitized text: 0 is benign, 1 is certainly an attack.
// Later layers (L1 v2, ONNX L2, embeddings L3, fusion) implement this and
// register themselves in Detectors.
type Detector interface {
	Score(ctx context.Context, sanitized string) (float64, error)
}

// DefaultDetector is the gateway's production detector.
const DefaultDetector = "fusion"

// Detectors maps a -detector flag value to a constructor.
var Detectors = map[string]func() (Detector, error){
	// regex is the legacy L1 v1 detector, kept for comparison.
	"regex": func() (Detector, error) {
		return RunnerDetector{Runner: inference.NewRegexRunner()}, nil
	},
	// fusion is the production detector: calibrated fusion of the layers
	// that exist (today L1 v2 rules), exactly as inference.NewRunner builds it.
	"fusion": func() (Detector, error) {
		r, err := inference.NewRunner("")
		if err != nil {
			return nil, err
		}
		return RunnerDetector{Runner: r}, nil
	},
	// l1 is the raw, uncalibrated L1 v2 rule score.
	"l1": func() (Detector, error) {
		f := fusion.New()
		f.Set(fusion.L1, fusion.RulesLayer{E: rules.New()}, fusion.Identity)
		return RunnerDetector{Runner: inference.NewRunnerWith(inference.FusedBackend{F: f})}, nil
	},
}

// DetectorNames lists the registered detectors.
func DetectorNames() []string {
	names := make([]string, 0, len(Detectors))
	for n := range Detectors {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RunnerDetector adapts the gateway's inference.Runner (chunking + max over chunks).
type RunnerDetector struct{ Runner *inference.Runner }

// Score implements Detector.
func (d RunnerDetector) Score(ctx context.Context, text string) (float64, error) {
	s, err := d.Runner.Scan(ctx, text)
	if err != nil {
		return 0, err
	}
	return float64(s.Injection.Confidence), nil
}

// Result is the pipeline outcome for one row.
type Result struct {
	Row      Row
	Score    float64 // detector score; 1 when the input was rejected
	Anomaly  float64 // sanitizer anomaly score
	Rejected bool    // sanitizer or scanner refused the input (gateway returns an error)
	Latency  time.Duration
}

// Production thresholds, mirrored from cmd/gateway.
const (
	InjectionBlockThreshold = 0.85
	AnomalyBlockThreshold   = 0.6
)

// GatewayBlocks reports the gateway's /v1/scan decision for this result.
func (r Result) GatewayBlocks() bool {
	return r.Rejected || r.Score >= InjectionBlockThreshold || r.Anomaly >= AnomalyBlockThreshold
}

// Run sends every row through the same input path as the gateway:
// sanitizer.Sanitize, then the detector on the sanitized text.
func Run(ctx context.Context, rows []Row, det Detector) ([]Result, error) {
	out := make([]Result, 0, len(rows))
	for _, row := range rows {
		start := time.Now()
		res := Result{Row: row}
		cleaned, rep, err := sanitizer.Sanitize(row.Text)
		if err != nil {
			res.Rejected, res.Score = true, 1
		} else {
			res.Anomaly = float64(rep.AnomalyScore)
			score, err := det.Score(ctx, cleaned)
			switch {
			case errors.Is(err, inference.ErrInputTooLong):
				res.Rejected, res.Score = true, 1
			case err != nil:
				return nil, fmt.Errorf("row %s: %w", row.ID, err)
			default:
				res.Score = score
			}
		}
		res.Latency = time.Since(start)
		out = append(out, res)
	}
	return out, nil
}
