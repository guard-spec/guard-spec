// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// testdata/window_parity.json pins the long path's windows for a set of EN,
// VI, code and log texts: the classifier tokenizer's content ids and byte
// offsets, and the windows (*model).longWindows cuts from them at 256 tokens
// with a 64-token overlap. The classifier is trained on the same windows
// (train/windows.py); train/tests/test_windows.py checks the Python side
// against this file, the tests here the Go side:
//
//   - TestWindowParityFixture (no build tag, runs in CI): longWindows and
//     chunk over the stored ids and offsets give the stored windows;
//   - TestWindowParityTokenizer (onnx && cgo, needs a classifier or e5
//     tokenizer.json, skips without one, as in CI): the tokenizer gives the
//     stored ids, offsets and special tokens.
//
// Regenerate after changing the texts or the tokenizer:
//
//	GUARDSPEC_WRITE_WINDOW_PARITY=1 go test -tags onnx -run TestWindowParityTokenizer ./internal/onnx/
const windowParityFile = "window_parity.json"

type parityWindow struct {
	Start     int `json:"start"` // content tokens [Start, End)
	End       int `json:"end"`
	ByteStart int `json:"byte_start"` // TokenWindow.Start, End
	ByteEnd   int `json:"byte_end"`
}

type parityText struct {
	Name    string         `json:"name"`
	Text    string         `json:"text"`
	IDs     []int64        `json:"ids"`
	Offsets [][2]int       `json:"offsets"`
	Windows []parityWindow `json:"windows"`
}

type parityFixture struct {
	Comment   string       `json:"comment"`
	Tokenizer string       `json:"tokenizer"`
	MaxLen    int          `json:"max_len"`
	Stride    int          `json:"stride"`
	Prefix    []int64      `json:"prefix"`
	Suffix    []int64      `json:"suffix"`
	Texts     []parityText `json:"texts"`
}

func readParityFixture(t *testing.T) parityFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", windowParityFile))
	if err != nil {
		t.Fatal(err)
	}
	var f parityFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// parityModel is a model with the fixture's geometry and special tokens; the
// window functions need nothing else.
func parityModel(f parityFixture) *model {
	return &model{prefix: f.Prefix, suffix: f.Suffix, maxLen: f.MaxLen, stride: f.Stride, maxChunks: -1}
}

// parityWindows are the windows of a text as the long path cuts them, with
// the content-token range of each.
func parityWindows(t *testing.T, m *model, text string, ids []int64, offs [][2]int) []parityWindow {
	t.Helper()
	step := m.maxLen - len(m.prefix) - len(m.suffix) - m.stride
	var out []parityWindow
	for i, w := range m.longWindows(text, ids, offs) {
		start := i * step
		want := slices.Concat(m.prefix, ids[start:start+w.Tokens], m.suffix)
		if !slices.Equal(w.IDs, want) {
			t.Fatalf("window %d: ids are not prefix + ids[%d:%d] + suffix", i, start, start+w.Tokens)
		}
		out = append(out, parityWindow{Start: start, End: start + w.Tokens, ByteStart: w.Start, ByteEnd: w.End})
	}
	// The short path (chunk, used by Score) cuts the same windows.
	chunks, err := m.chunk(ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != len(out) {
		t.Fatalf("chunk: %d windows, longWindows %d", len(chunks), len(out))
	}
	return out
}

func TestWindowParityFixture(t *testing.T) {
	f := readParityFixture(t)
	if f.MaxLen != 256 || f.Stride != 64 || len(f.Texts) == 0 {
		t.Fatalf("fixture geometry %d/%d, %d texts", f.MaxLen, f.Stride, len(f.Texts))
	}
	m := parityModel(f)
	multi := 0
	for _, x := range f.Texts {
		if len(x.IDs) == 0 && x.Text != "" {
			t.Fatalf("%s: no ids; regenerate the fixture", x.Name)
		}
		got := parityWindows(t, m, x.Text, x.IDs, x.Offsets)
		if !slices.Equal(got, x.Windows) {
			t.Errorf("%s: windows\n got %v\nwant %v", x.Name, got, x.Windows)
		}
		if len(got) > 1 {
			multi++
		}
	}
	if multi < 5 {
		t.Errorf("only %d texts span several windows", multi)
	}
}
