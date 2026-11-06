// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// Live is the detector the gateway scores with: the stack's fuser, whose L2
// classifier can be reloaded while the gateway serves traffic, plus the
// optional shadow candidate (shadow.go).
//
// A reload (Reload) resolves the target, checks every file against the
// manifest's SHA-256, loads the classifier fully and scores a warm-up text,
// and only then swaps the new generation in under a lock. Each Score holds the
// generation it started with until it returns, and so does each background
// shadow run; a retired generation's models are closed once nothing holds it.
// So a reload never fails or drops a request in flight, and any failure before
// the swap leaves the running models untouched.
type Live struct {
	stack     *Stack
	shadowCfg ShadowConfig
	slots     chan struct{} // shadow runs in flight

	mu  sync.RWMutex // guards cur
	cur *generation

	reloadMu sync.Mutex // one reload at a time; guards the targets
	l2       target
	shadow   target // zero: shadow off

	stMu       sync.Mutex // guards the fields below
	reloadedAt time.Time
	reloadErr  string
	shadowErr  string

	// load loads a classifier directory: LoadL2, replaced in tests.
	load func(dir string, o onnx.Options) (*L2Model, error)
}

// target is what a reload loads: a directory, a manifest reference, or (both
// empty) the manifest's recommended classifier.
type target struct{ ref, dir string }

func (t target) set() bool { return t.ref != "" || t.dir != "" }

type generation struct {
	id       int64
	fuser    *fusion.Fuser
	fusion   string
	l2       *L2Model     // nil: no L2
	shadow   *shadowModel // nil: shadow off
	inflight sync.WaitGroup
}

// close frees the generation's models once nothing holds it.
func (g *generation) close() {
	g.inflight.Wait()
	errs := []error{g.l2.Close()}
	if g.shadow != nil {
		errs = append(errs, g.shadow.m.Close())
	}
	if err := errors.Join(errs...); err != nil {
		slog.Warn("closing retired models", "generation", g.id, "err", err)
	}
}

// NewLive takes over the stack's classifier and loads the shadow candidate of
// cfg.Shadow. A candidate that does not load leaves shadow mode off and is
// reported in Status; it never stops the gateway.
func NewLive(s *Stack) *Live { return newLive(s, LoadL2) }

// NewLiveWithLoader is NewLive with another way to load a classifier
// directory than LoadL2, for tests that cannot run ONNX.
func NewLiveWithLoader(s *Stack, load func(dir string, o onnx.Options) (*L2Model, error)) *Live {
	return newLive(s, load)
}

func newLive(s *Stack, load func(string, onnx.Options) (*L2Model, error)) *Live {
	l := &Live{stack: s, shadowCfg: s.cfg.Shadow, load: load,
		l2: target{ref: s.cfg.L2Model, dir: s.cfg.L2Dir}}
	l.slots = make(chan struct{}, max(1, l.shadowCfg.MaxInFlight))
	if l.shadowCfg.Timeout <= 0 {
		l.shadowCfg.Timeout = defaultShadowTimeout
	}
	g := &generation{fuser: s.Fuser, fusion: s.Fusion, l2: s.l2}
	s.l2 = nil // owned by the generation from now on
	if s.cfg.Shadow.Enabled() {
		l.shadow = target{ref: s.cfg.Shadow.Model, dir: s.cfg.Shadow.Dir}
		m, err := l.loadShadow(l.shadow, false)
		if err != nil {
			l.shadowErr = err.Error()
			slog.Warn("shadow model not loaded; shadow mode is off", "err", err)
		} else {
			g.shadow = s.newShadow(m)
			slog.Info("shadow mode", "active", g.l2.Label(), "shadow", m.Label(),
				"timeout", l.shadowCfg.Timeout, "sample", l.shadowCfg.Sample, "max_inflight", cap(l.slots))
		}
	}
	l.cur = g
	if g.l2 != nil {
		go l.verifyRunning(g)
	}
	return l
}

// verifyRunning checks the classifier loaded at start against the manifest,
// for Status: a start never waits for (or fails on) it.
func (l *Live) verifyRunning(g *generation) {
	m := g.l2
	_, err := l.verify(m.Dir)
	l.stMu.Lock()
	m.Verified = err == nil
	l.stMu.Unlock()
	if err != nil {
		slog.Warn("L2: running classifier not verified against the manifest", "model", m.Label(), "err", err)
	}
}

// acquire returns the current generation, held until release.
func (l *Live) acquire() *generation {
	l.mu.RLock()
	defer l.mu.RUnlock()
	g := l.cur
	g.inflight.Add(1)
	return g
}

// Score implements inference.Scorer with the current generation. When ctx
// carries a Recorder and a shadow candidate is loaded, the candidate scores
// the same text in the background.
func (l *Live) Score(ctx context.Context, text string) fusion.Result {
	g := l.acquire()
	defer g.inflight.Done()
	r := g.fuser.Score(ctx, text)
	if g.shadow != nil {
		if rec := recorderFrom(ctx); rec != nil {
			l.runShadow(ctx, g, rec, text, r)
		}
	}
	return r
}

// Generation is the id of the running models; every reload changes it.
// Caches of scores key on it.
func (l *Live) Generation() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cur.id
}

// ShadowEnabled reports whether a candidate is loaded now.
func (l *Live) ShadowEnabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cur.shadow != nil
}

// ShadowConfig is the shadow configuration (timeout, sample rate).
func (l *Live) ShadowConfig() ShadowConfig { return l.shadowCfg }

// ReloadRequest says what to load. Empty fields keep the current targets, so
// a bare reload (SIGHUP) loads the same models again from disk: the files of
// a directory that changed in place, or the manifest's recommended version
// when no version was pinned.
type ReloadRequest struct {
	L2Model   string `json:"l2_model,omitempty"`     // name or name@version
	L2Dir     string `json:"l2_model_dir,omitempty"` // wins over L2Model
	Shadow    string `json:"shadow_l2_model,omitempty"`
	ShadowDir string `json:"shadow_l2_model_dir,omitempty"`
}

// ReloadResult describes the generation a reload swapped in.
type ReloadResult struct {
	Generation int64   `json:"generation"`
	L2Model    string  `json:"l2_model,omitempty"`
	Shadow     string  `json:"shadow_l2_model,omitempty"`
	Seconds    float64 `json:"seconds"`
}

// ErrReload wraps every reload failure; the running models are kept.
var ErrReload = errors.New("model reload failed; the running models are kept")

// Reload loads the targets of req and swaps them in. On any error the current
// generation keeps serving and the error is also reported by Status.
func (l *Live) Reload(ctx context.Context, req ReloadRequest) (ReloadResult, error) {
	start := time.Now()
	res, err := l.reload(ctx, req)
	l.stMu.Lock()
	l.reloadedAt = time.Now().UTC()
	l.reloadErr = ""
	if err != nil {
		l.reloadErr = err.Error()
	}
	l.stMu.Unlock()
	if err != nil {
		slog.Error("model reload failed; keeping the running models", "err", err)
		return res, fmt.Errorf("%w: %w", ErrReload, err)
	}
	res.Seconds = time.Since(start).Seconds()
	slog.Info("models reloaded", "generation", res.Generation, "l2_model", res.L2Model, "shadow", res.Shadow, "seconds", res.Seconds)
	return res, nil
}

func (l *Live) reload(ctx context.Context, req ReloadRequest) (ReloadResult, error) {
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ReloadResult{}, err
	}
	l2, shadow := l.l2, l.shadow
	switch {
	case req.L2Dir != "":
		l2 = target{dir: req.L2Dir}
	case req.L2Model != "":
		if _, _, err := onnx.ParseRef(req.L2Model); err != nil {
			return ReloadResult{}, err
		}
		l2 = target{ref: req.L2Model}
	}
	switch {
	case req.ShadowDir != "":
		shadow = target{dir: req.ShadowDir}
	case strings.EqualFold(req.Shadow, ShadowOff):
		shadow = target{}
	case req.Shadow != "":
		if _, _, err := onnx.ParseRef(req.Shadow); err != nil {
			return ReloadResult{}, err
		}
		shadow = target{ref: req.Shadow}
	}

	var (
		newL2  *L2Model
		newSh  *L2Model
		loaded []*L2Model
	)
	fail := func(err error) (ReloadResult, error) {
		for _, m := range loaded {
			_ = m.Close()
		}
		return ReloadResult{}, err
	}
	if l.stack.cfg.Layers[fusion.L2] {
		m, err := l.loadTarget("L2", l2, onnx.Options{IntraOpThreads: l.stack.threads})
		if err != nil {
			return fail(err)
		}
		newL2, loaded = m, append(loaded, m)
	} else if req.L2Dir != "" || req.L2Model != "" {
		return fail(fmt.Errorf("L2 is not in %s", EnvLayers))
	}
	if shadow.set() {
		m, err := l.loadShadow(shadow, true)
		if err != nil {
			return fail(err)
		}
		newSh, loaded = m, append(loaded, m)
	}
	for _, m := range loaded {
		if _, err := m.Layer.Score(ctx, "Reload check: summarize this paragraph."); err != nil {
			return fail(fmt.Errorf("%s: warm-up: %w", m.Label(), err))
		}
	}

	fuser, method := l.stack.assemble(newL2)
	g := &generation{fuser: fuser, fusion: method, l2: newL2}
	if newSh != nil {
		g.shadow = l.stack.newShadow(newSh)
	}
	l.mu.Lock()
	old := l.cur
	g.id = old.id + 1
	l.cur = g
	l.mu.Unlock()
	go old.close()

	l.l2, l.shadow = l2, shadow
	l.stMu.Lock()
	l.shadowErr = ""
	l.stMu.Unlock()
	res := ReloadResult{Generation: g.id, L2Model: newL2.Label()}
	if newSh != nil {
		res.Shadow = newSh.Label()
	}
	return res, nil
}

// loadShadow loads a candidate on its own ONNX limiter. On a reload
// (verified) its files must match the manifest like the active model's.
func (l *Live) loadShadow(t target, verified bool) (*L2Model, error) {
	o := onnx.Options{IntraOpThreads: l.stack.threads, Limiter: onnx.NewLimiter(cap(l.slots))}
	if !verified {
		dir, err := l.resolve(t)
		if err != nil {
			return nil, fmt.Errorf("shadow: %w", err)
		}
		m, err := l.load(dir, o)
		if err != nil {
			return nil, fmt.Errorf("shadow: %w", err)
		}
		m.Ref = RefForDir(l.stack.cfg.ModelDir, dir, l.manifestOrNil())
		_, verr := l.verify(dir)
		m.Verified = verr == nil
		return m, nil
	}
	return l.loadTarget("shadow", t, o)
}

// loadTarget resolves t, verifies its files against the manifest and loads it.
func (l *Live) loadTarget(what string, t target, o onnx.Options) (*L2Model, error) {
	dir, err := l.resolve(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	mod, err := l.verify(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	m, err := l.load(dir, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	m.Ref, m.Verified = mod.Ref(), true
	return m, nil
}

// resolve finds the directory of t like ResolveL2Dir does at start.
func (l *Live) resolve(t target) (string, error) {
	cfg := l.stack.cfg
	cfg.L2Dir, cfg.L2Model = t.dir, t.ref
	return ResolveL2Dir(cfg)
}

func (l *Live) manifestOrNil() *onnx.Manifest {
	m, err := l.stack.cfg.manifest()
	if err != nil {
		return nil
	}
	return m
}

// verify checks every file of the classifier in dir against the manifest
// entry it is an install of, and returns that entry. A directory that is no
// install of a manifest version cannot be verified and is refused.
func (l *Live) verify(dir string) (*onnx.ManifestModel, error) {
	m, err := l.stack.cfg.manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	ref := RefForDir(l.stack.cfg.ModelDir, dir, m)
	if ref == "" {
		return nil, fmt.Errorf("%s is not an install of a version in the manifest, so its SHA-256 cannot be checked "+
			"(install it with `models pull`, or list it in a manifest file named by %s)", dir, EnvManifest)
	}
	mod, err := m.Lookup(ref)
	if err != nil {
		return nil, err
	}
	for _, f := range mod.Files {
		if f.SHA256 == "" && f.GitSHA1 == "" {
			continue
		}
		if err := onnx.VerifyFile(filepath.Join(dir, f.Dest), f); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", ref, f.Dest, err)
		}
	}
	return mod, nil
}

// RefForDir names the manifest version that dir is an install of:
// MODEL_DIR/cache/<name>/<version>, or a directory from before versions
// named <name>-<version> when the manifest lists that version. "" otherwise.
func RefForDir(modelDir, dir string, m *onnx.Manifest) string {
	if rel, err := filepath.Rel(filepath.Join(modelDir, ModelCacheSubdir), dir); err == nil {
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) == 2 && parts[0] != ".." && parts[0] != "." {
			ref := parts[0] + "@" + parts[1]
			if _, _, err := onnx.ParseRef(ref); err == nil {
				return ref
			}
		}
	}
	if m == nil {
		return ""
	}
	base := filepath.Base(dir)
	for _, mod := range m.Models {
		if mod.Name+"-"+mod.Version == base {
			return mod.Ref()
		}
	}
	return ""
}

// Status is the detector part of /readyz that changes at run time.
type Status struct {
	Generation int64  `json:"generation"`
	L2Model    string `json:"l2_model,omitempty"` // name@version when known
	L2Verified bool   `json:"l2_verified"`
	Fusion     string `json:"fusion,omitempty"`
	// Recommended is the manifest's recommended classifier; UpdateAvailable
	// is true when it is a version of the running model's name other than
	// the running one. Installed lists the classifier versions in the cache.
	Recommended          string       `json:"recommended,omitempty"`
	RecommendedInstalled bool         `json:"recommended_installed"`
	UpdateAvailable      bool         `json:"update_available"`
	Installed            []string     `json:"installed"`
	Shadow               ShadowStatus `json:"shadow"`
	Reload               ReloadStatus `json:"reload"`
	ManifestError        string       `json:"manifest_error,omitempty"`
}

// ShadowStatus reports shadow mode.
type ShadowStatus struct {
	Enabled  bool    `json:"enabled"`
	Model    string  `json:"model,omitempty"`
	Verified bool    `json:"verified"`
	Sample   float64 `json:"sample"`
	Error    string  `json:"error,omitempty"`
}

// ReloadStatus reports the last reload.
type ReloadStatus struct {
	At    *time.Time `json:"at"`
	Error string     `json:"error,omitempty"`
}

// Status describes the running models and what the manifest offers. It reads
// the manifest and lists the cache, without hashing anything.
func (l *Live) Status() Status {
	l.mu.RLock()
	g := l.cur
	l.mu.RUnlock()
	st := Status{Generation: g.id, Fusion: g.fusion, Installed: []string{}}
	l.stMu.Lock()
	if g.l2 != nil {
		st.L2Model, st.L2Verified = g.l2.Label(), g.l2.Verified
	}
	st.Shadow = ShadowStatus{Enabled: g.shadow != nil, Sample: l.shadowCfg.Sample, Error: l.shadowErr}
	if g.shadow != nil {
		st.Shadow.Model, st.Shadow.Verified = g.shadow.m.Label(), g.shadow.m.Verified
	}
	if !l.reloadedAt.IsZero() {
		at := l.reloadedAt
		st.Reload.At = &at
	}
	st.Reload.Error = l.reloadErr
	l.stMu.Unlock()

	m, err := l.stack.cfg.manifest()
	if err != nil {
		st.ManifestError = err.Error()
		return st
	}
	cache := filepath.Join(l.stack.cfg.ModelDir, ModelCacheSubdir)
	st.Installed = installedClassifiers(m, cache)
	if rec := m.Recommended("classifier"); rec != nil {
		st.Recommended = rec.Ref()
		st.RecommendedInstalled = hasModel(rec.Dir(cache))
		if name, _, err := onnx.ParseRef(st.L2Model); err == nil && strings.Contains(st.L2Model, "@") {
			st.UpdateAvailable = name == rec.Name && st.L2Model != rec.Ref()
		}
	}
	return st
}

// installedClassifiers lists name@version for every version directory under
// the cache of a classifier the manifest names, listed there or not.
func installedClassifiers(m *onnx.Manifest, cache string) []string {
	names := map[string]bool{}
	for _, mod := range m.Models {
		if mod.Kind == "classifier" {
			names[mod.Name] = true
		}
	}
	out := []string{}
	for name := range names {
		entries, err := os.ReadDir(filepath.Join(cache, name))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && hasModel(filepath.Join(cache, name, e.Name())) {
				out = append(out, name+"@"+e.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}

// L2Name is the running classifier's name (thresholds.json "model"), "" without one.
func (l *Live) L2Name() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.cur.l2 == nil {
		return ""
	}
	return l.cur.l2.Name
}

// Fusion is the fusion method of the running generation.
func (l *Live) Fusion() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cur.fusion
}

// L1Floor is the L1 floor of the running generation (0: off or not used).
func (l *Live) L1Floor() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cur.fuser.L1Floor()
}

// Layers reports which layers run now: L2 follows the loaded generation.
func (l *Live) Layers() [3]bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	a := l.stack.Active
	a[fusion.L2] = l.cur.l2 != nil
	return a
}

// Problems are the stack's load problems, without the L2 one once a reload
// has loaded a classifier.
func (l *Live) Problems() []string {
	l.mu.RLock()
	hasL2 := l.cur.l2 != nil
	l.mu.RUnlock()
	var out []string
	for _, p := range l.stack.Problems {
		if hasL2 && strings.HasPrefix(p, "L2:") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Close frees every model once requests in flight are done.
func (l *Live) Close() error {
	l.mu.Lock()
	g := l.cur
	l.mu.Unlock()
	g.close()
	return l.stack.Close()
}
