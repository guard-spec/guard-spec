package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/onnx"
)

func installModel(t *testing.T, root, sub string) string {
	t.Helper()
	d := filepath.Join(root, sub)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, onnx.ConfigFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDefaultL2DirOrder: the manifest's recommended classifier first, then the
// directories from before versions: v3b, v2, v1, v0.
func TestDefaultL2DirOrder(t *testing.T) {
	root := t.TempDir()
	if got := DefaultL2Dir(root); got != "" {
		t.Fatalf("empty model dir: got %q", got)
	}
	for _, step := range []struct{ install, want string }{
		{L2DefaultV0, L2DefaultV0},
		{L2DefaultV1, L2DefaultV1},
		{L2DefaultV2, L2DefaultV2},
		{L2DefaultV3B, L2DefaultV3B},
		{"cache/guardspec-classifier/v3b", "cache/guardspec-classifier/v3b"},
	} {
		installModel(t, root, step.install)
		if got, want := DefaultL2Dir(root), filepath.Join(root, step.want); got != want {
			t.Errorf("after installing %s: got %q, want %q", step.install, got, want)
		}
	}
}

// TestResolveOrder: L2_MODEL_DIR, then L2_MODEL, then the recommended model,
// then the old layout; likewise for L3.
func TestResolveOrder(t *testing.T) {
	root := t.TempDir()
	env := func(m map[string]string) Config {
		m[EnvModelDir] = root
		cfg, err := ConfigFromEnv(func(k string) string { return m[k] })
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	// Nothing installed: the error names every directory tried.
	_, err := ResolveL2Dir(env(map[string]string{}))
	if err == nil || !strings.Contains(err.Error(), filepath.Join(root, "cache", "guardspec-classifier", "v3b")) ||
		!strings.Contains(err.Error(), filepath.Join(root, L2DefaultV0)) {
		t.Fatalf("nothing installed: %v", err)
	}

	old := installModel(t, root, L2DefaultV3B)
	rec := installModel(t, root, "cache/guardspec-classifier/v3b")
	older := installModel(t, root, "cache/guardspec-classifier/v2")
	oldL3 := installModel(t, root, L3DefaultSubdir)

	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"default is the recommended version", map[string]string{}, rec},
		{"name@version (rollback)", map[string]string{EnvL2Model: "guardspec-classifier@v2"}, older},
		{"bare name is the recommended version", map[string]string{EnvL2Model: "guardspec-classifier"}, rec},
		{"L2_MODEL_DIR wins", map[string]string{EnvL2Dir: old, EnvL2Model: "guardspec-classifier@v2"}, old},
		// An explicit choice is not replaced by another model when missing.
		{"missing version is not replaced", map[string]string{EnvL2Model: "guardspec-classifier@v9"},
			filepath.Join(root, "cache", "guardspec-classifier", "v9")},
		{"model outside the manifest", map[string]string{EnvL2Model: "my-classifier@2026-11"},
			filepath.Join(root, "cache", "my-classifier", "2026-11")},
	} {
		got, err := ResolveL2Dir(env(tc.env))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := ResolveL2Dir(env(map[string]string{EnvL2Model: "not-in-manifest"})); err == nil {
		t.Error("bare name outside the manifest: want error")
	}
	if _, err := ConfigFromEnv(func(k string) string { return map[string]string{EnvL2Model: "a@b@c"}[k] }); err == nil {
		t.Error("bad L2_MODEL: want a config error")
	}

	// L3: the old flat directory until the versioned one is installed.
	if got, err := ResolveL3Dir(env(map[string]string{})); err != nil || got != oldL3 {
		t.Errorf("L3 old layout: got %q, %v", got, err)
	}
	m, err := builtinManifest()
	if err != nil {
		t.Fatal(err)
	}
	e5 := m.Recommended("embedder")
	newL3 := installModel(t, root, filepath.Join("cache", e5.Name, e5.Version))
	if got, err := ResolveL3Dir(env(map[string]string{})); err != nil || got != newL3 {
		t.Errorf("L3 recommended: got %q, %v; want %q", got, err, newL3)
	}
	if got, _ := ResolveL3Dir(env(map[string]string{EnvL3Dir: "/x"})); got != "/x" {
		t.Errorf("L3_MODEL_DIR: got %q", got)
	}
}

// TestShippedCalibrationFile: the calibration.json published with each
// guardspec-classifier version of the manifest (v3b, v4) is the built-in
// calibration of that version, marshalled as `cmd/calibrate fit -write` does
// (two-space indent, trailing newline). To recreate it:
// json.MarshalIndent(BuiltinCalibrations["guardspec-classifier-<version>"], "", "  ") + "\n".
func TestShippedCalibrationFile(t *testing.T) {
	m, err := builtinManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v3b", "v4"} {
		mod, err := m.Lookup("guardspec-classifier@" + version)
		if err != nil {
			t.Fatal(err)
		}
		cal, ok := BuiltinCalibrations["guardspec-classifier-"+version]
		if !ok {
			t.Fatalf("no built-in calibration for %s", version)
		}
		data, err := json.MarshalIndent(cal, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		sum := sha256.Sum256(data)
		found := false
		for _, f := range mod.Files {
			if f.Dest != calibrationFile {
				continue
			}
			found = true
			if got := hex.EncodeToString(sum[:]); got != f.SHA256 || int64(len(data)) != f.Size {
				t.Errorf("%s: calibration.json in the manifest (%s, %d bytes) is not the built-in calibration (%s, %d bytes)",
					version, f.SHA256, f.Size, got, len(data))
			}
		}
		if !found {
			t.Errorf("guardspec-classifier@%s ships no calibration.json", version)
		}
	}
}
