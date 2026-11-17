//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// With the real classifier tokenizers, segmented tokenization gives exactly
// the tokens and offsets of the whole text, on English, Vietnamese, code and
// Markdown, and a model's tokenizer passes the split check.
func TestSegmentedTokensMatchWholeText(t *testing.T) {
	for _, name := range []string{"guardspec-classifier/v8e", "guardspec-classifier-v3b"} {
		t.Run(name, func(t *testing.T) {
			dir := modelDir(t, "L2_MODEL_DIR", name)
			tok, err := newHFTokenizer(filepath.Join(dir, TokenizerFile))
			if err != nil {
				t.Fatal(err)
			}
			defer tok.Close()
			if !splitExact(tok) {
				t.Fatal("the tokenizer does not split exactly")
			}
			var texts []string
			for _, p := range []string{"README.md", "README.vi.md", "CHANGELOG.md", "internal/onnx/long.go", "deploy/helm/guard-spec/values.yaml"} {
				b, err := os.ReadFile(filepath.Join(repoRoot(), p))
				if err != nil {
					t.Fatal(err)
				}
				texts = append(texts, string(b))
			}
			texts = append(texts, strings.Repeat("Dữ liệu  hai   khoảng trắng\n\n\tTab, emoji 😀 và 東京 ", 2000))
			for i, x := range texts {
				var s segmenter
				ids, offs, err := s.encode(tok, x)
				if err != nil {
					t.Fatal(err)
				}
				wantIDs, wantOffs, err := tok.EncodeOffsets(x)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(ids, wantIDs) || !reflect.DeepEqual(offs, wantOffs) {
					t.Fatalf("text %d (%d bytes, %d cuts): segmented tokens differ", i, len(x), len(segmentCuts(x)))
				}
			}
		})
	}
}
