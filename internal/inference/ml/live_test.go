// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// versionedClassifier is a fake classifier whose risk depends on the version
// it was "loaded" from. It fails once closed, so a request that used a
// retired model after its close would see L2 go missing.
type versionedClassifier struct {
	risk   float32
	delay  time.Duration
	err    error
	closed atomic.Bool
	calls  atomic.Int64
}

func (c *versionedClassifier) Score(ctx context.Context, _ []string) ([][]float32, error) {
	c.calls.Add(1)
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.closed.Load() {
		return nil, onnx.ErrClosed
	}
	if c.err != nil {
		return nil, c.err
	}
	return [][]float32{{1 - c.risk, c.risk, 0}}, nil
}
func (*versionedClassifier) Labels() []string {
	return []string{"benign", "direct_injection", "jailbreak"}
}
func (*versionedClassifier) BenignIndex() int { return 0 }
func (c *versionedClassifier) Close() error {
	c.closed.Store(true)
	return nil
}

// modelEnv is a MODEL_DIR with classifier versions installed in its cache and
// a manifest file that pins their files.
type modelEnv struct {
	dir, manifest string
	risks         map[string]float32 // version -> risk the fake returns
	delay         time.Duration
	failLoad      map[string]error
	failScore     map[string]error

	mu     sync.Mutex
	loaded []*versionedClassifier
}

func newModelEnv(t *testing.T, recommended string, versions map[string]float32) *modelEnv {
	t.Helper()
	e := &modelEnv{dir: t.TempDir(), risks: versions, failLoad: map[string]error{}, failScore: map[string]error{}}
	var b strings.Builder
	b.WriteString("models:\n")
	for v := range versions {
		d := filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", v)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{onnx.ConfigFile: `{"v":"` + v + `"}`, "model.onnx": "weights " + v}
		fmt.Fprintf(&b, "  - name: guardspec-classifier\n    version: %s\n    kind: classifier\n    recommended: %v\n"+
			"    repo: guard-spec/guardspec-classifier\n    revision: %s\n    license: Apache-2.0\n    files:\n",
			v, v == recommended, strings.Repeat("a", 40))
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(content))
			fmt.Fprintf(&b, "      - src: %s\n        dest: %s\n        size: %d\n        sha256: %s\n",
				name, name, len(content), hex.EncodeToString(sum[:]))
		}
	}
	e.manifest = filepath.Join(e.dir, "manifest.yaml")
	if err := os.WriteFile(e.manifest, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *modelEnv) load(dir string, _ onnx.Options) (*L2Model, error) {
	v := filepath.Base(dir)
	if err := e.failLoad[v]; err != nil {
		return nil, err
	}
	risk, ok := e.risks[v]
	if !ok {
		return nil, fmt.Errorf("%s: no model", dir)
	}
	c := &versionedClassifier{risk: risk, delay: e.delay, err: e.failScore[v]}
	e.mu.Lock()
	e.loaded = append(e.loaded, c)
	e.mu.Unlock()
	return NewL2Model(dir, c, c)
}

// live builds an L1+L2 stack (fusion max, identity calibration: the fused
// score is the larger of L1 and the fake's risk) and loads the first model
// with a reload, as the stub build cannot load one at start.
func (e *modelEnv) live(t *testing.T, first string, shadow ShadowConfig) *Live {
	t.Helper()
	cfg := Config{ModelDir: e.dir, Manifest: e.manifest, Layers: [3]bool{true, true, false}, Fusion: "max",
		L2Model: "guardspec-classifier@" + first, Shadow: shadow}
	s, err := Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l := newLive(s, e.load)
	t.Cleanup(func() { _ = l.Close() })
	if l.Status().L2Model == "" {
		if _, err := l.Reload(context.Background(), ReloadRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

// l2Of returns the calibrated L2 score of a benign text.
func l2Of(t *testing.T, l *Live) float64 {
	t.Helper()
	return l.Score(context.Background(), "Please summarize the attached quarterly report.").Layers[fusion.L2]
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestReloadSwapsModel(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.2, "v3b": 0.7})
	l := e.live(t, "v2", ShadowConfig{})
	if got := l2Of(t, l); !near(got, 0.2) {
		t.Fatalf("L2 = %v, want v2's 0.2", got)
	}
	st := l.Status()
	if st.L2Model != "guardspec-classifier@v2" || !st.L2Verified || !st.UpdateAvailable || st.Recommended != "guardspec-classifier@v3b" {
		t.Fatalf("status %+v", st)
	}
	if strings.Join(st.Installed, ",") != "guardspec-classifier@v2,guardspec-classifier@v3b" {
		t.Fatalf("installed %v", st.Installed)
	}
	res, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@v3b"})
	if err != nil {
		t.Fatal(err)
	}
	if res.L2Model != "guardspec-classifier@v3b" || res.Generation != st.Generation+1 {
		t.Fatalf("result %+v", res)
	}
	if got := l2Of(t, l); !near(got, 0.7) {
		t.Fatalf("L2 = %v after reload, want 0.7", got)
	}
	if st := l.Status(); st.UpdateAvailable || st.Reload.At == nil || st.Reload.Error != "" {
		t.Fatalf("status after reload %+v", st)
	}
	// A bare reload keeps the target chosen last.
	if res, err := l.Reload(context.Background(), ReloadRequest{}); err != nil || res.L2Model != "guardspec-classifier@v3b" {
		t.Fatalf("bare reload %+v %v", res, err)
	}
	// The retired classifiers are closed once nothing holds them.
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.mu.Lock()
		closed := 0
		for _, c := range e.loaded[:len(e.loaded)-1] {
			if c.closed.Load() {
				closed++
			}
		}
		n := len(e.loaded) - 1
		e.mu.Unlock()
		if closed == n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d retired classifiers closed", closed, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReloadUnderLoad scores from many goroutines while the model is
// reloaded back and forth: every request completes with L2 from one of the
// two versions, never from a closed model (run with -race).
func TestReloadUnderLoad(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.2, "v3b": 0.7})
	e.delay = 200 * time.Microsecond
	l := e.live(t, "v2", ShadowConfig{})

	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var served, bad atomic.Int64
	var badScore atomic.Value
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				got := l2Of(t, l)
				served.Add(1)
				if !near(got, 0.2) && !near(got, 0.7) {
					bad.Add(1)
					badScore.Store(got)
				}
			}
		}()
	}
	for i := range 20 {
		v := []string{"v3b", "v2"}[i%2]
		if _, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@" + v}); err != nil {
			t.Error(err)
		}
	}
	stop()
	wg.Wait()
	if bad.Load() > 0 {
		t.Fatalf("%d of %d requests saw a missing or wrong L2 score (e.g. %v)", bad.Load(), served.Load(), badScore.Load())
	}
	if served.Load() == 0 {
		t.Fatal("no request was served")
	}
	t.Logf("%d requests served during 20 reloads", served.Load())
}

func TestReloadFailureKeepsRunningModel(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.2, "v3b": 0.7, "v4": 0.9})
	l := e.live(t, "v2", ShadowConfig{})
	gen := l.Status().Generation

	// A file that does not match the manifest's SHA-256.
	if err := os.WriteFile(filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", "v3b", "model.onnx"),
		[]byte("tampered weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.failLoad["v4"] = errors.New("onnx: bad graph")
	outside := t.TempDir()
	cases := map[string]struct {
		req  ReloadRequest
		want string
	}{
		"sha mismatch":      {ReloadRequest{L2Model: "guardspec-classifier@v3b"}, "digest"},
		"load error":        {ReloadRequest{L2Model: "guardspec-classifier@v4"}, "bad graph"},
		"not in manifest":   {ReloadRequest{L2Dir: outside}, "not an install of a version in the manifest"},
		"unknown version":   {ReloadRequest{L2Model: "guardspec-classifier@v9"}, "v9"},
		"bad ref":           {ReloadRequest{L2Model: "a@b@c"}, "invalid model reference"},
		"bad shadow target": {ReloadRequest{Shadow: "guardspec-classifier@v3b"}, "digest"},
	}
	for name, tc := range cases {
		_, err := l.Reload(context.Background(), tc.req)
		if !errors.Is(err, ErrReload) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
		st := l.Status()
		if st.Generation != gen || st.L2Model != "guardspec-classifier@v2" || st.Reload.Error == "" || st.Shadow.Enabled {
			t.Errorf("%s: status %+v", name, st)
		}
		if got := l2Of(t, l); !near(got, 0.2) {
			t.Errorf("%s: L2 = %v, want the running v2's 0.2", name, got)
		}
	}
	// A model that loads but fails its warm-up is closed and not swapped in.
	e.risks["v5"] = 0.5
	e.failScore["v5"] = errors.New("session broken")
	addVersion(t, e, "v5")
	if _, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@v5"}); err == nil ||
		!strings.Contains(err.Error(), "warm-up") {
		t.Fatalf("warm-up failure: %v", err)
	}
	e.mu.Lock()
	last := e.loaded[len(e.loaded)-1]
	e.mu.Unlock()
	if !last.closed.Load() {
		t.Error("the model that failed its warm-up was not closed")
	}
	if got := l2Of(t, l); !near(got, 0.2) {
		t.Errorf("L2 = %v, want 0.2", got)
	}
	// A good reload clears the error.
	if _, err := l.Reload(context.Background(), ReloadRequest{}); err != nil {
		t.Fatal(err)
	}
	if st := l.Status(); st.Reload.Error != "" {
		t.Fatalf("error kept after a good reload: %+v", st.Reload)
	}
}

// addVersion installs one more version and rewrites the manifest with it.
func addVersion(t *testing.T, e *modelEnv, v string) {
	t.Helper()
	ne := newModelEnv(t, "v3b", map[string]float32{v: e.risks[v]})
	src := filepath.Join(ne.dir, ModelCacheSubdir, "guardspec-classifier", v)
	if err := os.Rename(src, filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", v)); err != nil {
		t.Fatal(err)
	}
	extra, err := os.ReadFile(ne.manifest)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(e.manifest)
	if err != nil {
		t.Fatal(err)
	}
	merged := string(old) + strings.TrimPrefix(string(extra), "models:\n")
	if err := os.WriteFile(e.manifest, []byte(merged), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestShadowComparesWithoutChangingTheResult(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.95, "v3b": 0.1})
	l := e.live(t, "v3b", ShadowConfig{Model: "guardspec-classifier@v2", Timeout: time.Second, Sample: 1, MaxInFlight: 4})
	st := l.Status()
	if !st.Shadow.Enabled || st.Shadow.Model != "guardspec-classifier@v2" || !st.Shadow.Verified {
		t.Fatalf("shadow status %+v", st.Shadow)
	}
	rec := NewRecorder()
	ctx := WithRecorder(context.Background(), rec)
	r := l.Score(ctx, "Please summarize the attached quarterly report.")
	if !near(r.Layers[fusion.L2], 0.1) {
		t.Fatalf("active L2 = %v: the shadow changed the result", r.Layers[fusion.L2])
	}
	l.Score(ctx, "And translate it to French.")
	res := rec.Wait(time.Second)
	if res.Status != ShadowOK || res.Texts != 2 || res.ActiveModel != "guardspec-classifier@v3b" ||
		res.ShadowModel != "guardspec-classifier@v2" || !near(res.ShadowL2, 0.95) || !near(res.ActiveL2, 0.1) ||
		!near(res.ShadowScore, 0.95) || res.ActiveScore > 0.5 {
		t.Fatalf("comparison %+v", res)
	}
	// No recorder in the context: nothing runs in the background.
	before := totalCalls(e)
	l.Score(context.Background(), "plain")
	time.Sleep(20 * time.Millisecond)
	if d := totalCalls(e) - before; d != 1 {
		t.Fatalf("%d classifier calls without a recorder, want 1 (active only)", d)
	}
	// Nothing scanned: no status.
	if res := NewRecorder().Wait(time.Millisecond); res.Status != "" {
		t.Fatalf("empty recorder: %+v", res)
	}
	// Shadow off by reload.
	if _, err := l.Reload(context.Background(), ReloadRequest{Shadow: ShadowOff}); err != nil {
		t.Fatal(err)
	}
	if l.ShadowEnabled() || l.Status().Shadow.Enabled {
		t.Fatal("shadow still on")
	}
	rec = NewRecorder()
	l.Score(WithRecorder(context.Background(), rec), "x")
	if res := rec.Wait(10 * time.Millisecond); res.Status != "" {
		t.Fatalf("shadow off but compared: %+v", res)
	}
}

func totalCalls(e *modelEnv) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var n int64
	for _, c := range e.loaded {
		n += c.calls.Load()
	}
	return n
}

func TestShadowBudget(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.95, "v3b": 0.1})
	l := e.live(t, "v3b", ShadowConfig{Model: "guardspec-classifier@v2", Timeout: 50 * time.Millisecond, Sample: 1, MaxInFlight: 1})
	// Make only the shadow slow: its classifier is the last one loaded.
	e.mu.Lock()
	var shadow *versionedClassifier
	for _, c := range e.loaded {
		if near(float64(c.risk), 0.95) {
			shadow = c
		}
	}
	e.mu.Unlock()
	shadow.delay = 200 * time.Millisecond

	rec := NewRecorder()
	ctx := WithRecorder(context.Background(), rec)
	start := time.Now()
	l.Score(ctx, "one")
	l.Score(ctx, "two") // the only slot is busy: skipped
	if d := time.Since(start); d > 40*time.Millisecond {
		t.Fatalf("active scoring took %v: it waited for the shadow", d)
	}
	res := rec.Wait(10 * time.Millisecond)
	if res.Status != ShadowTimeout {
		t.Fatalf("status %q, want timeout", res.Status)
	}
	// After the shadow's own deadline the run gives up and frees its slot.
	time.Sleep(100 * time.Millisecond)
	if res := rec.Wait(time.Second); res.Status != ShadowTimeout {
		t.Fatalf("status %q after the deadline, want timeout", res.Status)
	}
	rec = NewRecorder()
	ctx = WithRecorder(context.Background(), rec)
	shadow.delay = 0
	l.Score(ctx, "three")
	if res := rec.Wait(time.Second); res.Status != ShadowOK {
		t.Fatalf("status %q, want ok once the slot is free", res.Status)
	}
}

func TestShadowSkippedWhenBusy(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.95, "v3b": 0.1})
	l := e.live(t, "v3b", ShadowConfig{Model: "guardspec-classifier@v2", Timeout: time.Second, Sample: 1, MaxInFlight: 1})
	l.slots <- struct{}{} // every slot busy
	rec := NewRecorder()
	l.Score(WithRecorder(context.Background(), rec), "one")
	<-l.slots
	if res := rec.Wait(time.Second); res.Status != ShadowSkipped {
		t.Fatalf("status %q, want skipped", res.Status)
	}
}

func TestRefForDir(t *testing.T) {
	m, err := builtinManifest()
	if err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]string{
		"/m/cache/guardspec-classifier/v3b":   "guardspec-classifier@v3b",
		"/m/cache/guardspec-classifier":       "",
		"/m/local/guardspec-classifier-v3b":   "guardspec-classifier@v3b",
		"/m/local/guardspec-classifier-v2":    "",
		"/elsewhere/guardspec-classifier/v3b": "",
	} {
		if got := RefForDir("/m", dir, m); got != want {
			t.Errorf("%s: %q, want %q", dir, got, want)
		}
	}
}

func TestShadowConfigFromEnv(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	c, err := shadowConfigFromEnv(env(map[string]string{EnvShadowModel: "guardspec-classifier@v2",
		EnvShadowTimeout: "500ms", EnvShadowSample: "0.25", EnvShadowMaxInFlight: "3"}))
	if err != nil || !c.Enabled() || c.Timeout != 500*time.Millisecond || c.Sample != 0.25 || c.MaxInFlight != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := shadowConfigFromEnv(env(nil)); err != nil || c.Enabled() || c.Timeout != defaultShadowTimeout || c.Sample != 1 {
		t.Fatalf("defaults %+v %v", c, err)
	}
	for k, v := range map[string]string{EnvShadowModel: "a@b@c", EnvShadowTimeout: "0s", EnvShadowSample: "2",
		EnvShadowMaxInFlight: "0"} {
		if _, err := shadowConfigFromEnv(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}
