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
	"sync"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/models"
)

// Environment variables read by ConfigFromEnv.
const (
	EnvModelDir      = "MODEL_DIR"             // root of the model files (default ./models)
	EnvModelsPath    = "MODELS_PATH"           // older name of MODEL_DIR
	EnvL2Dir         = "L2_MODEL_DIR"          // classifier directory; wins over L2_MODEL
	EnvL3Dir         = "L3_MODEL_DIR"          // embedder directory; wins over L3_MODEL
	EnvL2Model       = "L2_MODEL"              // name[@version], e.g. guardspec-classifier@v3b
	EnvL3Model       = "L3_MODEL"              // name[@version], e.g. multilingual-e5-small@614241f
	ModelCacheSubdir = "cache"                 // where `models pull` installs <name>/<version>/
	EnvLayers        = "DETECTOR_LAYERS"       // e.g. l1,l2,l3 (default)
	EnvCascade       = "DETECTOR_CASCADE"      // true: skip L2/L3 when L1 is decisive
	EnvCascadeLow    = "DETECTOR_CASCADE_LOW"  // default DefaultCascade.Low
	EnvCascadeHigh   = "DETECTOR_CASCADE_HIGH" // default DefaultCascade.High
	EnvRequireML     = "DETECTOR_REQUIRE_ML"   // true: refuse to start without the ML layers (outside dev)
	EnvFusion        = "DETECTOR_FUSION"       // logreg (default) or max
	EnvL1Floor       = "FUSION_L1_FLOOR"       // calibrated L1 floor for decisive rules; 0 or off disables
	EnvManifest      = "MODELS_MANIFEST"       // manifest file; default: the copy built into the binary
	L2DefaultV3B     = "local/guardspec-classifier-v3b"
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

// DefaultL1Floor is the calibrated L1 score at or above which a decisive L1
// verdict (an override followed by its payload) bounds the fused score from
// below. Chosen on the classifier's validation splits (train/data/val.jsonl,
// val_hard.jsonl, val_vi_variants.jsonl, val_v3.jsonl: 5,840 rows), never on
// eval/: at 0.985 no benign row is floored and 73 of 1,654 attacks are; at
// 0.98 two benign rows would be ("bỏ wa tin nhắn trc của mình và gửi lại ...",
// L1 0.984).
const DefaultL1Floor = 0.985

// Config selects and locates the detection layers.
type Config struct {
	ModelDir string
	// L2Dir is the classifier directory. Empty: see ResolveL2Dir.
	L2Dir string
	// L2Model is a classifier reference, name or name@version, installed by
	// `models pull` in ModelDir/cache/<name>/<version>. Used when L2Dir is empty.
	L2Model string
	// L3Dir is the embedding model directory. Empty: see ResolveL3Dir.
	L3Dir string
	// L3Model is an embedder reference, like L2Model. Used when L3Dir is empty.
	L3Model string
	Layers  [3]bool // L1, L2, L3
	Cascade *fusion.Cascade
	// RequireML: a requested ML layer that cannot load is fatal (the gateway
	// applies this outside GUARD_ENV=dev only).
	RequireML bool
	// Fusion is "logreg" (the default: a fitted logistic regression over the
	// calibrated layers, max when no weights fit the active layers) or "max".
	Fusion string
	// L1Floor is FUSION_L1_FLOOR (default DefaultL1Floor; 0: off). It only
	// matters with the logreg combiner: max already keeps L1's score.
	L1Floor float64
	// Manifest is MODELS_MANIFEST: a manifest file read instead of the one
	// built into the binary, at start and on every reload, so that new
	// versions can be announced, verified and loaded without a new image.
	Manifest string
	// Shadow runs a candidate classifier next to the active one (shadow.go).
	Shadow ShadowConfig
}

// manifest is the manifest in effect: Manifest when set, else the built-in one.
func (c Config) manifest() (*onnx.Manifest, error) {
	if c.Manifest == "" {
		return builtinManifest()
	}
	return onnx.LoadManifest(c.Manifest)
}

// ConfigFromEnv reads the DETECTOR_*, *_MODEL and *_MODEL_DIR variables.
func ConfigFromEnv(get func(string) string) (Config, error) {
	cfg := Config{
		ModelDir: get(EnvModelDir),
		L2Dir:    get(EnvL2Dir), L2Model: strings.TrimSpace(get(EnvL2Model)),
		L3Dir: get(EnvL3Dir), L3Model: strings.TrimSpace(get(EnvL3Model)),
		Fusion: "logreg", L1Floor: DefaultL1Floor,
	}
	for _, kv := range [][2]string{{EnvL2Model, cfg.L2Model}, {EnvL3Model, cfg.L3Model}} {
		if kv[1] != "" {
			if _, _, err := onnx.ParseRef(kv[1]); err != nil {
				return Config{}, fmt.Errorf("%s: %w", kv[0], err)
			}
		}
	}
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
	if cfg.L1Floor, err = parseL1Floor(get(EnvL1Floor)); err != nil {
		return Config{}, err
	}
	cfg.Manifest = strings.TrimSpace(get(EnvManifest))
	if cfg.Shadow, err = shadowConfigFromEnv(get); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseL1Floor reads FUSION_L1_FLOOR: empty is the default, "off" or 0
// turns the floor off, anything else must be in (0.5, 1].
func parseL1Floor(v string) (float64, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "":
		return DefaultL1Floor, nil
	case "off", "false", "0":
		return 0, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0.5 || f > 1 {
		return 0, fmt.Errorf("%s must be off, 0 or a number in (0.5, 1]", EnvL1Floor)
	}
	return f, nil
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
	// L1Floor is the L1 floor in use with the logreg combiner (0: off or
	// not applicable).
	L1Floor float64

	cfg     Config
	threads int // ONNX intra-op threads per session; 0: ORT's choice
	l2      *L2Model
	closers []io.Closer // everything but l2
}

// L2Model is one loaded classifier with its calibration: what a reload
// swaps in, or what shadow mode runs next to the active one.
type L2Model struct {
	Dir   string // where it was loaded from
	Name  string // thresholds.json "model", else the directory name
	Ref   string // name@version when the directory is a manifest install, else ""
	Layer *ClassifierLayer
	Cal   CalibrationFile
	// CalSource is the calibration file, "built-in", or "" (raw scores).
	CalSource string
	// Verified is true when every file matched the manifest's SHA-256.
	Verified bool

	closer io.Closer
}

// Label is the model's name for logs, status and audit rows: Ref when known.
func (m *L2Model) Label() string {
	if m == nil {
		return ""
	}
	if m.Ref != "" {
		return m.Ref
	}
	return m.Name
}

// Close frees the classifier.
func (m *L2Model) Close() error {
	if m == nil || m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

// Close frees the models.
func (s *Stack) Close() error {
	errs := []error{s.l2.Close()}
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
	s := &Stack{cfg: cfg}
	s.Active[fusion.L1] = cfg.Layers[fusion.L1]
	if cfg.Layers[fusion.L2] && cfg.Layers[fusion.L3] && os.Getenv(onnx.EnvIntraOpThreads) == "" {
		// L2 and L3 run at the same time; split the cores between them rather
		// than letting both sessions claim all of them.
		s.threads = max(1, min(4, runtime.NumCPU()/2))
	}
	if cfg.Layers[fusion.L2] {
		if err := s.loadL2(cfg); err != nil {
			s.Problems = append(s.Problems, "L2: "+err.Error())
		}
	}
	if cfg.Layers[fusion.L3] {
		if err := s.loadL3(ctx, cfg, tenants, s.threads); err != nil {
			s.Problems = append(s.Problems, "L3: "+err.Error())
		}
	}
	s.Fuser, s.Fusion = s.assemble(s.l2)
	s.L1Floor = s.Fuser.L1Floor()
	return s, nil
}

// assemble builds a fuser over the stack's L1 and L3 and the classifier m
// (nil: no L2), with m's calibration and fusion weights. Build uses it, and so
// does a reload: L1 and L3 are shared, only L2 changes.
func (s *Stack) assemble(m *L2Model) (*fusion.Fuser, string) {
	f := fusion.New()
	if !s.Active[fusion.L1] {
		f.Set(fusion.L1, nil, fusion.Calibration{})
	}
	active := s.Active
	active[fusion.L2] = m != nil
	if m != nil {
		f.Set(fusion.L2, m.Layer, m.Cal.Platt)
	}
	if s.L3 != nil {
		f.Set(fusion.L3, s.L3, DefaultL3Calibration)
	}
	if s.cfg.Cascade != nil && s.Active[fusion.L1] {
		f.SetCascade(s.cfg.Cascade)
	}
	if s.cfg.Fusion == "logreg" && (active[fusion.L2] || active[fusion.L3]) {
		key := LayerKey(active)
		if lr, ok := combinerFor(m, key); ok {
			f.SetCombiner(&lr)
			if s.Active[fusion.L1] {
				f.SetL1Floor(s.cfg.L1Floor)
			}
			return f, "logreg"
		}
		slog.Warn("no logistic-regression weights for these layers; fusing with max",
			"model", m.Label(), "layers", key)
	}
	return f, "max"
}

// combinerFor is m's fusion weights for the layer set key. Without a
// classifier there is no source of weights, and fusion uses max.
func combinerFor(m *L2Model, key string) (fusion.LogReg, bool) {
	if m == nil {
		return fusion.LogReg{}, false
	}
	lr, ok := m.Cal.LogReg[key]
	return lr, ok
}

func (s *Stack) loadL2(cfg Config) error {
	dir, err := ResolveL2Dir(cfg)
	if err != nil {
		return err
	}
	m, err := LoadL2(dir, onnx.Options{IntraOpThreads: s.threads})
	if err != nil {
		return err
	}
	man, _ := cfg.manifest() // nil on error: no name for a directory outside the cache
	m.Ref = RefForDir(cfg.ModelDir, dir, man)
	s.l2 = m
	s.Active[fusion.L2] = true
	s.L2Dir, s.L2Model, s.L2 = dir, m.Name, m.Layer
	return nil
}

// LoadL2 loads the classifier in dir with its calibration (dir/calibration.json,
// else the built-in one for its name).
func LoadL2(dir string, o onnx.Options) (*L2Model, error) {
	c, err := onnx.NewClassifier(dir, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return NewL2Model(dir, c, c)
}

// NewL2Model wraps a loaded classifier; closer frees it (nil: nothing to free).
func NewL2Model(dir string, c Classifier, closer io.Closer) (*L2Model, error) {
	layer, err := NewClassifierLayer(c)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, err
	}
	name := modelName(dir)
	cal, src := calibrationFor(dir, name)
	if src == "" {
		slog.Warn("L2: no calibration for this classifier; using raw scores. Fit one with `go run -tags onnx ./cmd/calibrate fit -write`",
			"dir", dir, "model", name)
	}
	slog.Info("L2 classifier loaded", "dir", dir, "model", name, "calibration", src, "A", cal.Platt.A, "B", cal.Platt.B)
	return &L2Model{Dir: dir, Name: name, Layer: layer, Cal: cal, CalSource: src, closer: closer}, nil
}

func (s *Stack) loadL3(ctx context.Context, cfg Config, tenants TenantStore, threads int) error {
	dir, err := ResolveL3Dir(cfg)
	if err != nil {
		return err
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
	s.Active[fusion.L3] = true
	s.L3 = layer
	s.closers = append(s.closers, e)
	a, b := ix.Len()
	slog.Info("L3 embeddings loaded", "dir", dir, "attack_exemplars", a, "benign_exemplars", b, "per_org", tc != nil)
	return nil
}

// L2Defaults are the classifier directories under MODEL_DIR from before
// versioned models, newest first. They are searched only when the manifest's
// recommended classifier is not installed. v3 never shipped (it failed the
// eval set), so it is not searched.
var L2Defaults = []string{L2DefaultV3B, L2DefaultV2, L2DefaultV1, L2DefaultV0}

// L3Defaults are the embedder directories under MODEL_DIR from before
// versioned models.
var L3Defaults = []string{L3DefaultSubdir}

// builtinManifest is models/manifest.yaml as built into the binary.
var builtinManifest = sync.OnceValues(func() (*onnx.Manifest, error) {
	return onnx.ParseManifest(models.Manifest)
})

// ResolveL2Dir picks the classifier directory, in this order:
//
//  1. L2_MODEL_DIR (Config.L2Dir), as is;
//  2. L2_MODEL=name@version: MODEL_DIR/cache/<name>/<version>; a bare name
//     is its recommended version in the manifest;
//  3. the manifest's recommended classifier, MODEL_DIR/cache/<name>/<version>,
//     when installed;
//  4. the directories from before versions (L2Defaults), the first installed.
//
// Steps 1 and 2 are explicit choices: the directory is returned even when it
// holds no model, and loading it then fails (no silent fallback to another
// model). An error from 3-4 lists every directory tried.
func ResolveL2Dir(cfg Config) (string, error) {
	return resolveDir(cfg.manifest, cfg.ModelDir, cfg.L2Dir, cfg.L2Model, EnvL2Model, "classifier", L2Defaults)
}

// ResolveL3Dir picks the embedder directory, in the order of ResolveL2Dir
// with L3_MODEL_DIR, L3_MODEL and L3Defaults.
func ResolveL3Dir(cfg Config) (string, error) {
	return resolveDir(cfg.manifest, cfg.ModelDir, cfg.L3Dir, cfg.L3Model, EnvL3Model, "embedder", L3Defaults)
}

func resolveDir(manifest func() (*onnx.Manifest, error), modelDir, dir, ref, refEnv, kind string, legacy []string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	m, merr := manifest()
	if ref != "" {
		name, version, err := onnx.ParseRef(ref)
		if err != nil {
			return "", fmt.Errorf("%s: %w", refEnv, err)
		}
		if version == "" {
			if merr != nil {
				return "", fmt.Errorf("%s=%s needs a version (built-in manifest: %v)", refEnv, ref, merr)
			}
			mod, ok := m.Find(name)
			if !ok {
				return "", fmt.Errorf("%s=%s: not in the manifest; give name@version", refEnv, ref)
			}
			version = mod.Version
		}
		return filepath.Join(modelDir, ModelCacheSubdir, name, version), nil
	}
	var tried []string
	if merr == nil {
		if mod := m.Recommended(kind); mod != nil {
			d := mod.Dir(filepath.Join(modelDir, ModelCacheSubdir))
			if hasModel(d) {
				return d, nil
			}
			tried = append(tried, d)
		}
	}
	for _, sub := range legacy {
		d := filepath.Join(modelDir, sub)
		if hasModel(d) {
			return d, nil
		}
		tried = append(tried, d)
	}
	return "", fmt.Errorf("no %s in %s (run `models pull`, see docs/models.md)", kind, strings.Join(tried, ", "))
}

func hasModel(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, onnx.ConfigFile))
	return err == nil
}

// DefaultL2Dir is the classifier directory used when neither L2_MODEL_DIR
// nor L2_MODEL is set, or "" when none is installed.
func DefaultL2Dir(modelDir string) string {
	d, err := ResolveL2Dir(Config{ModelDir: modelDir})
	if err != nil {
		return ""
	}
	return d
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
