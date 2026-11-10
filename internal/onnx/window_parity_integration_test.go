//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// parityTokenizer is the tokenizer.json the classifier ships with (v3b and
// v4 package the base model's tokenizer), else the e5 base model's copy.
func parityTokenizer(t *testing.T) string {
	t.Helper()
	var cands []string
	if d := os.Getenv("GUARDSPEC_CLASSIFIER_DIR"); d != "" {
		cands = append(cands, filepath.Join(d, TokenizerFile))
	}
	for _, n := range []string{"local/guardspec-classifier-v3b", "local/guardspec-classifier-v4", "cache/multilingual-e5-small"} {
		cands = append(cands, filepath.Join(repoRoot(), "models", filepath.FromSlash(n), TokenizerFile))
	}
	for _, p := range cands {
		if fileExists(p) {
			return p
		}
	}
	t.Skipf("no tokenizer.json in %v; run `go run ./cmd/models pull`", cands)
	return ""
}

// TestWindowParityTokenizer checks the fixture's ids, offsets and special
// tokens against the tokenizer (see window_parity_test.go). With
// GUARDSPEC_WRITE_WINDOW_PARITY=1 it rewrites them, and the windows, from
// the fixture's texts.
func TestWindowParityTokenizer(t *testing.T) {
	path := parityTokenizer(t)
	tok, err := newHFTokenizer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tok.Close() }()
	f := readParityFixture(t)
	prefix, suffix := tok.Specials()
	if os.Getenv("GUARDSPEC_WRITE_WINDOW_PARITY") == "1" {
		f.Comment = "Written by internal/onnx/window_parity_integration_test.go (GUARDSPEC_WRITE_WINDOW_PARITY=1); " +
			"offsets are byte offsets; windows as (*model).longWindows cuts them. Read by train/tests/test_windows.py."
		f.Tokenizer = "intfloat/multilingual-e5-small@614241f tokenizer.json (as packaged with guardspec-classifier-v3b)"
		f.MaxLen, f.Stride, f.Prefix, f.Suffix = 256, 64, prefix, suffix
		m := parityModel(f)
		for i := range f.Texts {
			x := &f.Texts[i]
			if x.IDs, x.Offsets, err = tok.EncodeOffsets(x.Text); err != nil {
				t.Fatal(err)
			}
			x.Windows = parityWindows(t, m, x.Text, x.IDs, x.Offsets)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", windowParityFile), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote testdata/%s from %s", windowParityFile, path)
		return
	}
	if !slices.Equal(prefix, f.Prefix) || !slices.Equal(suffix, f.Suffix) {
		t.Errorf("special tokens %v/%v, fixture %v/%v", prefix, suffix, f.Prefix, f.Suffix)
	}
	for _, x := range f.Texts {
		ids, offs, err := tok.EncodeOffsets(x.Text)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ids, x.IDs) || !slices.Equal(offs, x.Offsets) {
			t.Errorf("%s: tokenizer output differs from the fixture (%d ids, fixture %d)", x.Name, len(ids), len(x.IDs))
		}
	}
}
