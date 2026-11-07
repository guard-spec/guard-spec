// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitIdentity polls Identity until the background hash is done.
func waitIdentity(t *testing.T, l *Live) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if id, ok := l.Identity(); ok {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatal("model identity not computed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestModelIdentity(t *testing.T) {
	e := newModelEnv(t, "v3b", map[string]float32{"v2": 0.2, "v3b": 0.7})
	a := waitIdentity(t, e.live(t, "v2", ShadowConfig{}))
	if len(a) != 64 {
		t.Fatalf("identity %q", a)
	}
	// Another process with the same models and configuration: the same
	// identity, although its generation counter may differ.
	if b := waitIdentity(t, e.live(t, "v2", ShadowConfig{})); b != a {
		t.Errorf("same models, identities %s and %s", a, b)
	}

	// A reload to another version changes it; reloading back restores it.
	l := e.live(t, "v2", ShadowConfig{})
	if _, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@v3b"}); err != nil {
		t.Fatal(err)
	}
	v3b := waitIdentity(t, l)
	if v3b == a {
		t.Error("another classifier version kept the identity")
	}
	if _, err := l.Reload(context.Background(), ReloadRequest{L2Model: "guardspec-classifier@v2"}); err != nil {
		t.Fatal(err)
	}
	if got := waitIdentity(t, l); got != a {
		t.Error("reloading the first version did not restore its identity")
	}

	// Detector configuration that changes scores changes it: fusion method,
	// L1 floor, cascade, layers.
	build := func(mut func(*Config)) string {
		cfg := Config{ModelDir: e.dir, Manifest: e.manifest, Layers: [3]bool{true, true, false}, Fusion: "max",
			L2Model: "guardspec-classifier@v2"}
		mut(&cfg)
		s, err := Build(context.Background(), cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		l := newLive(s, e.load)
		t.Cleanup(func() { _ = l.Close() })
		if l.Status().L2Model == "" && cfg.Layers[1] {
			if _, err := l.Reload(context.Background(), ReloadRequest{}); err != nil {
				t.Fatal(err)
			}
		}
		return waitIdentity(t, l)
	}
	if build(func(*Config) {}) != a {
		t.Error("identical configuration, other identity")
	}
	seen := map[string]string{a: "base"}
	for name, mut := range map[string]func(*Config){
		"cascade": func(c *Config) { c.Cascade = &DefaultCascade },
		"l1 only": func(c *Config) { c.Layers = [3]bool{true, false, false} },
	} {
		id := build(mut)
		if prev, ok := seen[id]; ok {
			t.Errorf("%s has the identity of %s", name, prev)
		}
		seen[id] = name
	}

	// The classifier's files are part of it, not only its name: a
	// calibration.json added to the same version directory (which the
	// manifest does not list, so verification passes) changes the scores and
	// so the identity.
	dir := filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", "v2")
	if err := os.WriteFile(filepath.Join(dir, "calibration.json"), []byte(`{"platt":{"A":2,"B":0}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitIdentity(t, e.live(t, "v2", ShadowConfig{})); got == a {
		t.Error("a new calibration file kept the identity")
	}
	if got := hashDir(dir); got == hashDir(filepath.Join(e.dir, ModelCacheSubdir, "guardspec-classifier", "v3b")) {
		t.Error("two directories hash alike")
	}
	before := hashDir(dir)
	if err := os.WriteFile(filepath.Join(dir, "model.onnx"), []byte("other weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	if hashDir(dir) == before {
		t.Error("changed weights, same hash")
	}
	if hashDir(filepath.Join(e.dir, "missing")) == hashDir(filepath.Join(e.dir, "missing2")) {
		t.Error("unreadable directories hash alike")
	}
}
