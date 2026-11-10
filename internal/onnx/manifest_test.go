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
	"strings"
	"sync"
	"testing"
)

const testRev = "0123456789012345678901234567890123456789"

func TestRepoManifestIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	m, err := LoadManifest(filepath.Join(filepath.Dir(file), "..", "..", "models", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"protectai-deberta-v3-small-pi-v2", "multilingual-e5-small", "guardspec-classifier"} {
		if _, ok := m.Find(name); !ok {
			t.Errorf("manifest lacks %s", name)
		}
	}
	if c := m.Recommended("classifier"); c == nil || c.Ref() != "guardspec-classifier@v3b" {
		t.Errorf("recommended classifier: %+v", c)
	}
	if e := m.Recommended("embedder"); e == nil || e.Name != "multilingual-e5-small" {
		t.Errorf("recommended embedder: %+v", e)
	}
	c, err := m.Lookup("guardspec-classifier@v3b")
	if err != nil {
		t.Fatal(err)
	}
	var dests []string
	for _, f := range c.Files {
		dests = append(dests, f.Dest)
	}
	if got := strings.Join(dests, ","); got != "model_int8.onnx,tokenizer.json,config.json,thresholds.json,calibration.json" {
		t.Errorf("guardspec-classifier files: %s", got)
	}
	if len(c.Mirrors) == 0 || !strings.Contains(c.Mirrors[0], "/releases/download/model-guardspec-classifier-v3b/") {
		t.Errorf("guardspec-classifier mirrors: %v", c.Mirrors)
	}
	// v4 and v5: candidates next to v3b (shadow mode first), with the same files.
	for _, version := range []string{"v4", "v5"} {
		ref := "guardspec-classifier@" + version
		cand, err := m.Lookup(ref)
		if err != nil {
			t.Fatal(err)
		}
		if cand.Recommended {
			t.Errorf("%s must not be recommended before the owner switches the default", ref)
		}
		dests = dests[:0]
		for _, f := range cand.Files {
			dests = append(dests, f.Dest)
		}
		if got := strings.Join(dests, ","); got != "model_int8.onnx,tokenizer.json,config.json,thresholds.json,calibration.json" {
			t.Errorf("%s files: %s", ref, got)
		}
		if len(cand.Mirrors) == 0 || !strings.Contains(cand.Mirrors[0], "/releases/download/model-guardspec-classifier-"+version+"/") {
			t.Errorf("%s mirrors: %v", ref, cand.Mirrors)
		}
	}
}

func digests(b []byte) (s256, gitSHA string) {
	sum := sha256.Sum256(b)
	h := sha1.New() //nolint:gosec
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(sum[:]), hex.EncodeToString(h.Sum(nil))
}

func TestPullVerifiesDigests(t *testing.T) {
	good := []byte("hello model")
	s256, gitSHA := digests(good)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/org/repo/resolve/"+testRev+"/gated.json" && r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(good)
	}))
	defer srv.Close()

	mod := ManifestModel{
		Name: "m", Version: "v1", Repo: "org/repo", Revision: testRev, License: "MIT",
		Files: []ManifestFile{
			{Src: "a.bin", Dest: "model.onnx", Size: int64(len(good)), SHA256: s256},
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
	if b, _ := os.ReadFile(filepath.Join(dir, "m", "v1", "model.onnx")); string(b) != string(good) {
		t.Fatal("content not written to <dir>/<name>/<version>/")
	}
	if !Installed(&mod, dir) {
		t.Fatal("not installed after pull")
	}
	// Second pull keeps verified files.
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}

	// Without the token the gated file is refused.
	if err := os.Remove(filepath.Join(dir, "m", "v1", "config.json")); err != nil {
		t.Fatal(err)
	}
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

// fileServer serves files[path] and records the requests it saw.
type fileServer struct {
	mu    sync.Mutex
	files map[string][]byte
	seen  []string
	auth  []string
}

func (s *fileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.URL.Path)
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	b, ok := s.files[r.URL.Path]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b)
}

func TestPullFallsBackToMirror(t *testing.T) {
	body := []byte("classifier weights")
	sum, _ := digests(body)
	hf := &fileServer{files: map[string][]byte{}} // primary: everything 404s
	hfSrv := httptest.NewServer(hf)
	defer hfSrv.Close()
	mirror := &fileServer{files: map[string][]byte{"/rel/model_int8.onnx": body}}
	mirrorSrv := httptest.NewTLSServer(mirror)
	defer mirrorSrv.Close()

	mod := ManifestModel{
		Name: "c", Version: "v2", Repo: "org/c", Revision: testRev, License: "MIT",
		Mirrors: []string{mirrorSrv.URL + "/rel/" + MirrorFilePlaceholder},
		Files:   []ManifestFile{{Src: "onnx/model_int8.onnx", Dest: "model_int8.onnx", Size: int64(len(body)), SHA256: sum}},
	}
	if err := (&Manifest{Models: []ManifestModel{mod}}).Validate(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := &Puller{Client: mirrorSrv.Client(), BaseURL: hfSrv.URL, Token: "secret"}
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if len(hf.seen) != 1 || len(mirror.seen) != 1 {
		t.Fatalf("want one primary and one mirror request, got %v / %v", hf.seen, mirror.seen)
	}
	if hf.auth[0] != "Bearer secret" || mirror.auth[0] != "" {
		t.Fatalf("HF_TOKEN must go to Hugging Face only: hf=%q mirror=%q", hf.auth[0], mirror.auth[0])
	}
	if !Installed(&mod, dir) {
		t.Fatal("not installed")
	}

	// A model not on Hugging Face yet skips it entirely.
	mod.Version, mod.Revision = "v3", UnpinnedRevision
	hf.seen = nil
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if len(hf.seen) != 0 {
		t.Fatalf("unpinned revision still asked Hugging Face: %v", hf.seen)
	}

	// A mirror that serves wrong bytes is refused like any other source.
	mirror.files["/rel/model_int8.onnx"] = []byte("tampered weights!!")
	mod.Version = "v4"
	if err := p.Pull(context.Background(), &mod, dir); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c", "v4")); !os.IsNotExist(err) {
		t.Fatalf("failed pull created the version directory: %v", err)
	}
}

func TestPullUserMirrorFirst(t *testing.T) {
	body := []byte("e5")
	sum, _ := digests(body)
	local := &fileServer{files: map[string][]byte{"/models/e/1/model.onnx": body}}
	srv := httptest.NewServer(local)
	defer srv.Close()
	mod := ManifestModel{Name: "e", Version: "1", Repo: "o/e", Revision: testRev, License: "MIT",
		Files: []ManifestFile{{Src: "onnx/model.onnx", Dest: "model.onnx", Size: int64(len(body)), SHA256: sum}}}
	p := &Puller{BaseURL: "http://127.0.0.1:1", Mirror: srv.URL + "/models/", Token: "secret"}
	if err := p.Pull(context.Background(), &mod, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if len(local.seen) != 1 || local.auth[0] != "" {
		t.Fatalf("mirror requests %v auth %v", local.seen, local.auth)
	}
}

// TestPullIsAtomic: a failed pull never touches a version in place, and a
// complete one reuses verified files (also from the layout before versions).
func TestPullIsAtomic(t *testing.T) {
	a, b := []byte("file a"), []byte("file b")
	sa, _ := digests(a)
	sb, _ := digests(b)
	srv := &fileServer{files: map[string][]byte{"/o/r/resolve/" + testRev + "/b": b}}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	mod := ManifestModel{Name: "n", Version: "v1", Repo: "o/r", Revision: testRev, License: "MIT",
		Files: []ManifestFile{
			{Src: "a", Dest: "a.json", Size: int64(len(a)), SHA256: sa},
			{Src: "b", Dest: "b.json", Size: int64(len(b)), SHA256: sb},
		}}
	dir := t.TempDir()
	// The old layout holds a; b only comes from the server.
	if err := os.MkdirAll(filepath.Join(dir, "n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "n", "a.json"), a, 0o644); err != nil {
		t.Fatal(err)
	}
	// An incomplete install with a corrupt file.
	vdir := filepath.Join(dir, "n", "v1")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vdir, "b.json"), []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Server down: the pull fails and the version directory stays as it was.
	p := &Puller{BaseURL: "http://127.0.0.1:1"}
	if err := p.Pull(context.Background(), &mod, dir); err == nil {
		t.Fatal("want error")
	}
	if got, _ := os.ReadFile(filepath.Join(vdir, "b.json")); string(got) != "corrupt" {
		t.Fatalf("failed pull changed the install: %q", got)
	}
	assertNoTemp(t, filepath.Join(dir, "n"))

	p.BaseURL = hs.URL
	if err := p.Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if !Installed(&mod, dir) {
		t.Fatal("not installed")
	}
	if len(srv.seen) != 1 {
		t.Fatalf("a.json should come from the old layout, b.json from the server: %v", srv.seen)
	}
	assertNoTemp(t, filepath.Join(dir, "n"))

	// Installed and verified: nothing is downloaded.
	srv.seen = nil
	if err := p.Pull(context.Background(), &mod, dir); err != nil || len(srv.seen) != 0 {
		t.Fatalf("second pull: err %v, requests %v", err, srv.seen)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left behind %s", e.Name())
		}
	}
}

func TestManifestLookup(t *testing.T) {
	f := []ManifestFile{{Src: "x", Dest: "model.onnx", SHA256: strings.Repeat("0", 64)}}
	m := &Manifest{Models: []ManifestModel{
		{Name: "c", Version: "v1", Repo: "o/r", Revision: testRev, License: "MIT", Files: f},
		{Name: "c", Version: "v2", Recommended: true, Kind: "classifier", Repo: "o/r", Revision: testRev, License: "MIT", Files: f},
		{Name: "e", Version: "1", Kind: "embedder", Repo: "o/e", Revision: testRev, License: "MIT", Files: f},
	}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]string{"c": "c@v2", "c@v1": "c@v1", "e": "e@1", " c@v2 ": "c@v2"} {
		mod, err := m.Lookup(ref)
		if err != nil || mod.Ref() != want {
			t.Errorf("Lookup(%q) = %v, %v; want %s", ref, mod, err, want)
		}
	}
	for _, ref := range []string{"c@v9", "x", "c@", "@v1", "c@v1@v2", "../c", "c@.."} {
		if _, err := m.Lookup(ref); err == nil {
			t.Errorf("Lookup(%q): want error", ref)
		}
	}
	var refs []string
	for _, d := range m.Defaults() {
		refs = append(refs, d.Ref())
	}
	if got := strings.Join(refs, " "); got != "c@v2 e@1" {
		t.Errorf("Defaults: %s", got)
	}
	if r := m.Recommended("embedder"); r != nil {
		t.Errorf("e is not marked recommended: %v", r)
	}
}

func TestManifestValidation(t *testing.T) {
	base := func() ManifestModel {
		return ManifestModel{Name: "m", Version: "v1", Repo: "o/r", Revision: testRev, License: "MIT",
			Files: []ManifestFile{{Src: "x", Dest: "model.onnx", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}}
	}
	cases := map[string]func(*ManifestModel){
		"branch revision":         func(m *ManifestModel) { m.Revision = "main" },
		"no digest":               func(m *ManifestModel) { m.Files[0].SHA256 = "" },
		"path traversal":          func(m *ManifestModel) { m.Files[0].Dest = "../x" },
		"no license":              func(m *ManifestModel) { m.License = "" },
		"git sha no size":         func(m *ManifestModel) { m.Files[0].GitSHA1 = "0123456789012345678901234567890123456789" },
		"no version":              func(m *ManifestModel) { m.Version = "" },
		"version traversal":       func(m *ManifestModel) { m.Version = ".." },
		"version with slash":      func(m *ManifestModel) { m.Version = "a/b" },
		"unpinned without mirror": func(m *ManifestModel) { m.Revision = UnpinnedRevision },
		"http mirror":             func(m *ManifestModel) { m.Mirrors = []string{"http://x/{file}"} },
		"mirror without {file}":   func(m *ManifestModel) { m.Mirrors = []string{"https://x/model"} },
	}
	for name, mut := range cases {
		m := base()
		mut(&m)
		if err := (&Manifest{Models: []ManifestModel{m}}).Validate(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	dup := base()
	if err := (&Manifest{Models: []ManifestModel{base(), dup}}).Validate(); err == nil {
		t.Error("duplicate name@version: want error")
	}
	two := base()
	two.Version, two.Recommended = "v2", true
	one := base()
	one.Recommended = true
	if err := (&Manifest{Models: []ManifestModel{one, two}}).Validate(); err == nil {
		t.Error("two recommended versions: want error")
	}
	two.Recommended = false
	if err := (&Manifest{Models: []ManifestModel{one, two}}).Validate(); err != nil {
		t.Errorf("two versions of one model: %v", err)
	}
}
