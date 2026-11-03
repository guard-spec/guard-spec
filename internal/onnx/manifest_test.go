package onnx

import (
	"context"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRepoManifestIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	m, err := LoadManifest(filepath.Join(filepath.Dir(file), "..", "..", "models", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"protectai-deberta-v3-small-pi-v2", "multilingual-e5-small"} {
		if _, ok := m.Find(name); !ok {
			t.Errorf("manifest lacks %s", name)
		}
	}
}

func TestPullVerifiesDigests(t *testing.T) {
	good := []byte("hello model")
	s256 := sha256.Sum256(good)
	h := sha1.New() //nolint:gosec
	fmt.Fprintf(h, "blob %d\x00", len(good))
	h.Write(good)
	gitSHA := hex.EncodeToString(h.Sum(nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/org/repo/resolve/0123456789012345678901234567890123456789/gated.json" && r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(good)
	}))
	defer srv.Close()

	mod := ManifestModel{
		Name: "m", Repo: "org/repo", Revision: "0123456789012345678901234567890123456789", License: "MIT",
		Files: []ManifestFile{
			{Src: "a.bin", Dest: "model.onnx", Size: int64(len(good)), SHA256: hex.EncodeToString(s256[:])},
			{Src: "gated.json", Dest: "config.json", Size: int64(len(good)), GitSHA1: gitSHA},
		},
	}
	if err := (&Manifest{Models: []ManifestModel{mod}}).Validate(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := &Puller{BaseURL: srv.URL, Token: "tok"}
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "m", "model.onnx")); string(b) != string(good) {
		t.Fatal("content not written")
	}
	// Second pull keeps verified files.
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}

	// Without the token the gated file is refused.
	os.Remove(filepath.Join(dir, "m", "config.json"))
	if err := (&Puller{BaseURL: srv.URL}).Pull(context.Background(), &mod, dir); err == nil {
		t.Fatal("want 401 error")
	}

	// A wrong digest is refused and nothing is left behind.
	bad := mod
	bad.Name = "bad"
	bad.Files = []ManifestFile{{Src: "a.bin", Dest: "model.onnx", Size: int64(len(good)), SHA256: hex.EncodeToString(make([]byte, 32))}}
	err := p.Pull(context.Background(), &bad, dir)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "bad"))
	if len(entries) != 0 {
		t.Fatalf("mismatched download left files: %v", entries)
	}
}

func TestManifestValidation(t *testing.T) {
	base := func() ManifestModel {
		return ManifestModel{Name: "m", Repo: "o/r", Revision: "0123456789012345678901234567890123456789", License: "MIT",
			Files: []ManifestFile{{Src: "x", Dest: "model.onnx", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}}
	}
	cases := map[string]func(*ManifestModel){
		"branch revision": func(m *ManifestModel) { m.Revision = "main" },
		"no digest":       func(m *ManifestModel) { m.Files[0].SHA256 = "" },
		"path traversal":  func(m *ManifestModel) { m.Files[0].Dest = "../x" },
		"no license":      func(m *ManifestModel) { m.License = "" },
		"git sha no size": func(m *ManifestModel) { m.Files[0].GitSHA1 = "0123456789012345678901234567890123456789" },
	}
	for name, mut := range cases {
		m := base()
		mut(&m)
		if err := (&Manifest{Models: []ManifestModel{m}}).Validate(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
