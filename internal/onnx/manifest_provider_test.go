// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A model with a GPU-only file: the CPU never downloads it, cuda and auto
// do, and its absence never makes an install incomplete.
func TestManifestProviderFiles(t *testing.T) {
	int8, fp16 := []byte("int8 model"), []byte("fp16 model")
	s8, _ := digests(int8)
	s16, _ := digests(fp16)
	var mu sync.Mutex
	got := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[filepath.Base(r.URL.Path)]++
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, ModelFP16File) {
			_, _ = w.Write(fp16)
			return
		}
		_, _ = w.Write(int8)
	}))
	defer srv.Close()

	mod := ManifestModel{
		Name: "m", Version: "v1", Repo: "org/repo", Revision: testRev, License: "MIT",
		Files: []ManifestFile{
			{Src: ModelInt8File, Dest: ModelInt8File, Size: int64(len(int8)), SHA256: s8},
			{Src: ModelFP16File, Dest: ModelFP16File, Size: int64(len(fp16)), SHA256: s16, Provider: ProviderCUDA},
		},
	}
	if err := (&Manifest{Models: []ManifestModel{mod}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if n := len(mod.FilesFor(ProviderCPU)); n != 1 {
		t.Fatalf("cpu files: %d", n)
	}
	if n, m := len(mod.FilesFor(ProviderCUDA)), len(mod.FilesFor(ProviderAuto)); n != 2 || m != 2 {
		t.Fatalf("cuda files: %d, auto: %d", n, m)
	}

	dir := t.TempDir()
	vdir := mod.Dir(dir)
	if err := (&Puller{BaseURL: srv.URL}).Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if got[ModelFP16File] != 0 || !Installed(&mod, dir) || InstalledFor(&mod, dir, ProviderCUDA) {
		t.Fatalf("cpu pull: requests %v", got)
	}
	if !mod.Files[1].SkipIfAbsent(vdir) || mod.Files[0].SkipIfAbsent(vdir) {
		t.Fatal("SkipIfAbsent: only the absent provider file may be skipped")
	}

	// cuda adds the GPU file and keeps the verified INT8 one.
	if err := (&Puller{BaseURL: srv.URL, Provider: ProviderCUDA}).Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if got[ModelFP16File] != 1 || got[ModelInt8File] != 1 || !InstalledFor(&mod, dir, ProviderCUDA) {
		t.Fatalf("cuda pull: requests %v", got)
	}
	if mod.Files[1].SkipIfAbsent(vdir) {
		t.Fatal("a present provider file must be verified")
	}

	// A tampered GPU file is not installed for cuda, and the next pull replaces it.
	if err := os.WriteFile(filepath.Join(vdir, ModelFP16File), []byte("tampered!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if InstalledFor(&mod, dir, ProviderCUDA) || !Installed(&mod, dir) {
		t.Fatal("tampered fp16: wrong install state")
	}
	if err := (&Puller{BaseURL: srv.URL, Provider: ProviderAuto}).Pull(context.Background(), &mod, dir); err != nil {
		t.Fatal(err)
	}
	if !InstalledFor(&mod, dir, ProviderCUDA) {
		t.Fatal("auto pull did not repair the fp16 file")
	}
}

func TestManifestProviderValidation(t *testing.T) {
	base := func(f ManifestFile) *Manifest {
		return &Manifest{Models: []ManifestModel{{Name: "m", Version: "v1", Repo: "o/r", Revision: testRev, License: "MIT",
			Files: []ManifestFile{{Src: "a", Dest: "a", SHA256: strings.Repeat("a", 64)}, f}}}}
	}
	if err := base(ManifestFile{Src: "b", Dest: "b", SHA256: strings.Repeat("b", 64), Provider: "rocm"}).Validate(); err == nil {
		t.Error("provider rocm accepted")
	}
	if err := base(ManifestFile{Src: "b", Dest: "b", Size: 3, GitSHA1: strings.Repeat("b", 40), Provider: ProviderCUDA}).Validate(); err == nil {
		t.Error("a provider file without sha256 accepted")
	}
	if p := ManifestProvider(envMap(EnvProvider, "bogus")); p != ProviderCPU {
		t.Errorf("invalid INFERENCE_PROVIDER: %s", p)
	}
	if p := ManifestProvider(envMap(EnvProvider, "auto")); p != ProviderAuto {
		t.Errorf("auto: %s", p)
	}
}
