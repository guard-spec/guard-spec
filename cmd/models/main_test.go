// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/guard-spec/guard-spec/internal/onnx"
)

func TestInitRefs(t *testing.T) {
	cases := []struct {
		layers, l2 string
		refs       []string
		need       bool
	}{
		{"", "", nil, true},
		{"l1,l2,l3", "guardspec-classifier@v4", nil, true},
		{"l1, L3", "", nil, true},
		{"l1,l2", "", []string{"guardspec-classifier"}, true},
		{"l1,l2", "guardspec-classifier@v4", []string{"guardspec-classifier@v4"}, true},
		{"l1", "", nil, false},
	}
	for _, c := range cases {
		env := map[string]string{"DETECTOR_LAYERS": c.layers, "L2_MODEL": c.l2}
		refs, need := initRefs(func(k string) string { return env[k] })
		if need != c.need || !reflect.DeepEqual(refs, c.refs) {
			t.Errorf("layers %q L2_MODEL %q: got %v %v, want %v %v", c.layers, c.l2, refs, need, c.refs, c.need)
		}
	}
}

// testManifest has one model served only from the mirror of srv.
func testManifest(t *testing.T, srv *httptest.Server, body []byte) *onnx.Manifest {
	t.Helper()
	sum := sha256.Sum256(body)
	return &onnx.Manifest{Models: []onnx.ManifestModel{{
		Name: "guardspec-classifier", Version: "v9", Recommended: true, Kind: "classifier",
		Repo: "guard-spec/test", Revision: onnx.UnpinnedRevision,
		Mirrors: []string{srv.URL + "/{file}"},
		Files:   []onnx.ManifestFile{{Src: "model.onnx", Dest: "model.onnx", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}},
	}}}
}

func TestInit(t *testing.T) {
	body := []byte("model bytes")
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer ok.Close()
	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()

	cases := []struct {
		name     string
		srv      *httptest.Server
		layers   string
		required bool
		code     int
		pulled   bool
	}{
		{"pulls", ok, "l1,l2,l3", false, 0, true},
		{"l1 needs nothing", missing, "l1", true, 0, false},
		{"failure warns", missing, "l1,l2,l3", false, 0, false},
		{"failure is fatal when required", missing, "l1,l2", true, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DETECTOR_LAYERS", c.layers)
			t.Setenv("L2_MODEL", "")
			dir := t.TempDir()
			o := options{dir: dir, required: c.required}
			var out bytes.Buffer
			code, err := run(context.Background(), "init", o, testManifest(t, c.srv, body), &out)
			if err != nil {
				t.Fatal(err)
			}
			if code != c.code {
				t.Fatalf("exit %d, want %d; output:\n%s", code, c.code, out.String())
			}
			_, statErr := os.Stat(filepath.Join(dir, "guardspec-classifier", "v9", "model.onnx"))
			if pulled := statErr == nil; pulled != c.pulled {
				t.Fatalf("pulled %v, want %v", pulled, c.pulled)
			}
		})
	}
}

func TestParseArgsRequired(t *testing.T) {
	t.Setenv("DETECTOR_REQUIRE_ML", "")
	t.Setenv("MODELS_REQUIRED", "true")
	o, err := parseArgs("init", []string{"-dir", "/models/cache"})
	if err != nil || !o.required {
		t.Fatalf("MODELS_REQUIRED=true: required %v, err %v", o.required, err)
	}
	t.Setenv("MODELS_REQUIRED", "")
	if o, _ = parseArgs("init", nil); o.required {
		t.Fatal("required without the variables")
	}
}
