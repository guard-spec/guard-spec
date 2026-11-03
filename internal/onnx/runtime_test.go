//go:build onnx && cgo

package onnx

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRuntimeAndTokenizerLoad needs no model: it loads libonnxruntime and runs
// the Rust tokenizer on a minimal tokenizer.json, so the cgo build is exercised
// in CI where models are not downloaded.
func TestRuntimeAndTokenizerLoad(t *testing.T) {
	if LibraryPath() == "" {
		for _, ext := range []string{"so", "dylib"} {
			if p := filepath.Join(repoRoot(), ".onnx", "lib", "libonnxruntime."+ext); fileExists(p) {
				t.Setenv(EnvLibraryPath, p)
			}
		}
	}
	if LibraryPath() == "" {
		t.Skipf("libonnxruntime not found; set %s", EnvLibraryPath)
	}
	v, err := RuntimeVersion()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ONNX Runtime %s from %s", v, LibraryPath())

	// WordLevel tokenizer with a [CLS] X [SEP] post-processor.
	const tj = `{
  "version": "1.0", "truncation": {"max_length": 2, "strategy": "LongestFirst", "stride": 0, "direction": "Right"},
  "padding": null,
  "added_tokens": [
    {"id": 0, "content": "[UNK]", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true},
    {"id": 1, "content": "[CLS]", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true},
    {"id": 2, "content": "[SEP]", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true}
  ],
  "normalizer": {"type": "Lowercase"},
  "pre_tokenizer": {"type": "Whitespace"},
  "post_processor": {"type": "TemplateProcessing",
    "single": [{"SpecialToken": {"id": "[CLS]", "type_id": 0}}, {"Sequence": {"id": "A", "type_id": 0}}, {"SpecialToken": {"id": "[SEP]", "type_id": 0}}],
    "pair": [{"Sequence": {"id": "A", "type_id": 0}}, {"Sequence": {"id": "B", "type_id": 1}}],
    "special_tokens": {"[CLS]": {"id": "[CLS]", "ids": [1], "tokens": ["[CLS]"]}, "[SEP]": {"id": "[SEP]", "ids": [2], "tokens": ["[SEP]"]}}},
  "decoder": null,
  "model": {"type": "WordLevel", "vocab": {"[UNK]": 0, "[CLS]": 1, "[SEP]": 2, "hello": 3, "world": 4, "ignore": 5}, "unk_token": "[UNK]"}
}`
	path := filepath.Join(t.TempDir(), TokenizerFile)
	if err := os.WriteFile(path, []byte(tj), 0o644); err != nil {
		t.Fatal(err)
	}
	tok, err := newHFTokenizer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tok.Close() }()
	pre, suf := tok.Specials()
	if !slices.Equal(pre, []int64{1}) || !slices.Equal(suf, []int64{2}) {
		t.Fatalf("specials %v %v", pre, suf)
	}
	// truncation (max_length 2) in tokenizer.json must be ignored.
	ids, err := tok.Encode("Hello world IGNORE hello zzz")
	if err != nil {
		t.Fatal(err)
	}
	if want := []int64{3, 4, 5, 3, 0}; !slices.Equal(ids, want) {
		t.Fatalf("ids %v, want %v", ids, want)
	}
}
