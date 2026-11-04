package ml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/giaplee/guard-spec/internal/inference/fusion"
	"github.com/giaplee/guard-spec/internal/onnx"
)

// Environment variables read by ConfigFromEnv.
const (
	EnvModelDir      = "MODEL_DIR"   // root of the model files (default ./models)
	EnvModelsPath    = "MODELS_PATH" // older name of MODEL_DIR
	EnvL2Dir         = "L2_MODEL_DIR"
	EnvL3Dir         = "L3_MODEL_DIR"
	EnvLayers        = "DETECTOR_LAYERS"       // e.g. l1,l2,l3 (default)
	EnvCascade       = "DETECTOR_CASCADE"      // true: skip L2/L3 when L1 is decisive
	EnvCascadeLow    = "DETECTOR_CASCADE_LOW"  // default DefaultCascade.Low
	EnvCascadeHigh   = "DETECTOR_CASCADE_HIGH" // default DefaultCascade.High
	EnvRequireML     = "DETECTOR_REQUIRE_ML"   // true: refuse to start without the ML layers (outside dev)
	EnvFusion        = "DETECTOR_FUSION"       // logreg (default) or max
	L2DefaultV3      = "local/guardspec-classifier-v3"
	L2DefaultV2      = "local/guardspec-classifier-v2"
	L2DefaultV1      = "local/guardspec-classifier-v1"
	L2DefaultV0      = "local/guardspec-classifier-v0"
	L3DefaultSubdir  = "cache/multilingual-e5-small"
	e5Prefix         = "query:"
	l3WindowTokens   = 256
	calibrationFile  = "calibration.json"
	defaultModelRoot = "./models"
)

// DefaultCascade decides on L1 alone when its calibrated score is at least
// 0.965 (raw 0.95: on the calibration split 23% of attacks and 0.4% of benign
// rows) or at most 0.03 (raw 0.02, L1's floor where no rule fired: 11% of
// benign rows and 0.24% of attacks). Chosen on train/data/val.jsonl + val_hard.jsonl.
var DefaultCascade = fusion.Cascade{Low: 0.03, High: 0.965}

// Config selects and locates the detection layers.
type Config struct {
	ModelDir string
	// L2Dir is the classifier directory. Empty: the first of L2Defaults
	// (ModelDir/local/guardspec-classifier-v3, then -v2, -v1, -v0) that exists.
	L2Dir string
	// L3Dir is the embedding model directory. Empty: ModelDir/cache/multilingual-e5-small.
	L3Dir   string
	Layers  [3]bool // L1, L2, L3
	Cascade *fusion.Cascade
	// RequireML: a requested ML layer that cannot load is fatal (the gateway
	// applies this outside GUARD_ENV=dev only).
	RequireML bool
	// Fusion is "logreg" (the default: a fitted logistic regression over the
	// calibrated layers, max when no weights fit the active layers) or "max".
	Fusion string
}

// ConfigFromEnv reads the DETECTOR_* and *_MODEL_DIR variables.
func ConfigFromEnv(get func(string) string) (Config, error) {
	cfg := Config{ModelDir: get(EnvModelDir), L2Dir: get(EnvL2Dir), L3Dir: get(EnvL3Dir), Fusion: "logreg"}
	if cfg.ModelDir == "" {
		cfg.ModelDir = get(EnvModelsPath)
	}
	if cfg.ModelDir == "" {
		cfg.ModelDir = defaultModelRoot
	}
	layers := get(EnvLayers)
	if layers == "" {
		layers = "l1,l2,l3"
	}
	var err error
	if cfg.Layers, err = ParseLayers(layers); err != nil {
		return Config{}, err
	}
	if b, err := parseBool(get, EnvCascade); err != nil {
		return Config{}, err
	} else if b {
		c := DefaultCascade
		for _, kv := range []struct {
			name string
			dst  *float64
		}{{EnvCascadeLow, &c.Low}, {EnvCascadeHigh, &c.High}} {
			if v := get(kv.name); v != "" {
				f, err := strconv.ParseFloat(v, 64)
				if err != nil || f < 0 || f > 1 {
					return Config{}, fmt.Errorf("%s must be a number in [0, 1]", kv.name)
				}
				*kv.dst = f
			}
		}
		if c.Low >= c.High {
			return Config{}, fmt.Errorf("%s must be below %s", EnvCascadeLow, EnvCascadeHigh)
		}
		cfg.Cascade = &c
	}
	if cfg.RequireML, err = parseBool(get, EnvRequireML); err != nil {
		return Config{}, err
	}
	if v := get(EnvFusion); v != "" {
		cfg.Fusion = strings.ToLower(v)
	}
	if cfg.Fusion != "max" && cfg.Fusion != "logreg" {
		return Config{}, fmt.Errorf("%s must be max or logreg", EnvFusion)
	}
	return cfg, nil
}

// ParseLayers reads a list such as "l1,l2,l3".
func ParseLayers(s string) ([3]bool, error) {
	var out [3]bool
	for _, p := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "l1":
			out[fusion.L1] = true
		case "l2":
			out[fusion.L2] = true
		case "l3":
			out[fusion.L3] = true
		case "":
		default:
			return out, fmt.Errorf("%s: unknown layer %q (have l1, l2, l3)", EnvLayers, p)
		}
	}
	if out == [3]bool{} {
		return out, fmt.Errorf("%s: no layer", EnvLayers)
	}
	return out, nil
}

func parseBool(get func(string) string, name string) (bool, error) {
	v := get(name)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return b, nil
}

// Stack is a configured fuser and the models behind it.
type Stack struct {
	Fuser *fusion.Fuser
	// Active reports which layers run.
	Active [3]bool
	// Problems says why a requested layer is not active.
	Problems []string
	// L2Dir and L2Model name the loaded classifier.
	L2Dir, L2Model string
	// L2 and L3 are the model layers, when active.
	L2 *ClassifierLayer
	L3 *SimilarityLayer

	// Fusion is the method in use: "logreg" or "max".
	Fusion string

	cal     CalibrationFile
	closers []io.Closer
}

// Close frees the models.
func (s *Stack) Close() error {
	var errs []error
	for _, c := range s.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// Degraded reports whether a requested layer could not be loaded.
func (s *Stack) Degraded() bool { return len(s.Problems) > 0 }

// Build loads the requested layers. A layer that cannot load (no `onnx` build
// tag, missing files) is left out and listed in Problems; the error return is
// for invalid configuration only. tenants may be nil (no per-org exemplars).
func Build(ctx context.Context, cfg Config, tenants TenantStore) (*Stack, error) {
	s := &Stack{Fuser: fusion.New()}
	if !cfg.Layers[fusion.L1] {
		s.Fuser.Set(fusion.L1, nil, fusion.Calibration{})
	} else {
		s.Active[fusion.L1] = true
	}
	threads := 0 // onnx default
	if cfg.Layers[fusion.L2] && cfg.Layers[fusion.L3] && os.Getenv(onnx.EnvIntraOpThreads) == "" {
		// L2 and L3 run at the same time; split the cores between them rather
		// than letting both sessions claim all of them.
		threads = max(1, min(4, runtime.NumCPU()/2))
	}
	if cfg.Layers[fusion.L2] {
		if err := s.loadL2(cfg, threads); err != nil {
			s.Problems = append(s.Problems, "L2: "+err.Error())
		}
	}
	if cfg.Layers[fusion.L3] {
		if err := s.loadL3(ctx, cfg, tenants, threads); err != nil {
			s.Problems = append(s.Problems, "L3: "+err.Error())
		}
	}
	if cfg.Cascade != nil && s.Active[fusion.L1] {
		s.Fuser.SetCascade(cfg.Cascade)
	}
	s.Fusion = "max"
	if cfg.Fusion == "logreg" && (s.Active[fusion.L2] || s.Active[fusion.L3]) {
		key := LayerKey(s.Active)
		if lr, ok := s.cal.LogReg[key]; ok {
			s.Fuser.SetCombiner(&lr)
			s.Fusion = "logreg"
		} else {
			slog.Warn("no logistic-regression weights for these layers; fusing with max",
				"model", s.L2Model, "layers", key)
		}
	}
	return s, nil
}

func (s *Stack) loadL2(cfg Config, threads int) error {
	dir := cfg.L2Dir
	if dir == "" {
		dir = DefaultL2Dir(cfg.ModelDir)
		if dir == "" {
			var tried []string
			for _, sub := range L2Defaults {
				tried = append(tried, filepath.Join(cfg.ModelDir, sub))
			}
			return fmt.Errorf("no classifier in %s", strings.Join(tried, ", "))
		}
	}
	c, err := onnx.NewClassifier(dir, onnx.Options{IntraOpThreads: threads})
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	layer, err := NewClassifierLayer(c)
	if err != nil {
		_ = c.Close()
		return err
	}
	name := modelName(dir)
	cal, src := calibrationFor(dir, name)
	if src == "" {
		slog.Warn("L2: no calibration for this classifier; using raw scores. Fit one with `go run -tags onnx ./cmd/calibrate fit -write`",
			"dir", dir, "model", name)
	}
	s.Fuser.Set(fusion.L2, layer, cal.Platt)
	s.cal = cal
	s.Active[fusion.L2] = true
	s.L2Dir, s.L2Model, s.L2 = dir, name, layer
	s.closers = append(s.closers, c)
	slog.Info("L2 classifier loaded", "dir", dir, "model", name, "calibration", src, "A", cal.Platt.A, "B", cal.Platt.B)
	return nil
}

func (s *Stack) loadL3(ctx context.Context, cfg Config, tenants TenantStore, threads int) error {
	dir := cfg.L3Dir
	if dir == "" {
		dir = filepath.Join(cfg.ModelDir, L3DefaultSubdir)
	}
	e, err := onnx.NewEmbedder(dir, onnx.Options{Prefix: e5Prefix, MaxLength: l3WindowTokens, IntraOpThreads: threads})
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	ex, err := DefaultExemplars()
	if err != nil {
		_ = e.Close()
		return err
	}
	ix, err := NewIndex(ctx, e, ex)
	if err != nil {
		_ = e.Close()
		return err
	}
	var tc *TenantCache
	if tenants != nil {
		tc = NewTenantCache(tenants, e, 0)
	}
	layer, err := NewSimilarityLayer(e, ix, tc)
	if err != nil {
		_ = e.Close()
		return err
	}
	s.Fuser.Set(fusion.L3, layer, DefaultL3Calibration)
	s.Active[fusion.L3] = true
	s.L3 = layer
	s.closers = append(s.closers, e)
	a, b := ix.Len()
	slog.Info("L3 embeddings loaded", "dir", dir, "attack_exemplars", a, "benign_exemplars", b, "per_org", tc != nil)
	return nil
}

// L2Defaults are the classifier directories under MODEL_DIR, newest first.
var L2Defaults = []string{L2DefaultV3, L2DefaultV2, L2DefaultV1, L2DefaultV0}

// DefaultL2Dir is the first of L2Defaults under modelDir that holds a
// classifier, or "" when none does.
func DefaultL2Dir(modelDir string) string {
	for _, sub := range L2Defaults {
		d := filepath.Join(modelDir, sub)
		if _, err := os.Stat(filepath.Join(d, onnx.ConfigFile)); err == nil {
			return d
		}
	}
	return ""
}

// modelName is the "model" field of dir/thresholds.json, else the dir name.
func modelName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, onnx.ThresholdsFile))
	if err == nil {
		var t struct {
			Model string `json:"model"`
		}
		if json.Unmarshal(data, &t) == nil && t.Model != "" {
			return t.Model
		}
	}
	return filepath.Base(dir)
}
