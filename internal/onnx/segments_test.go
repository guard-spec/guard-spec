// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// wordTokenizer gives one token per word, with the space before it, as a
// Metaspace tokenizer does; joinSpaces makes it inexact across a split.
type wordTokenizer struct {
	calls, bytes atomic.Int64
	joinSpaces   bool
}

func (w *wordTokenizer) EncodeOffsets(text string) ([]int64, [][2]int, error) {
	w.calls.Add(1)
	w.bytes.Add(int64(len(text)))
	var ids []int64
	var offs [][2]int
	start := -1
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == ' ' {
			if start >= 0 && i > start {
				var h int64 = 7
				for _, c := range []byte(text[start:i]) {
					h = h*31 + int64(c)
				}
				if w.joinSpaces && start == 0 {
					h++ // the first word of a text is tokenized differently
				}
				ids, offs = append(ids, h%50000), append(offs, [2]int{start, i})
			}
			start = i
		}
	}
	return ids, offs, nil
}

func longText(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString("word")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(" ")
		if i%13 == 0 {
			b.WriteString("\n\n  ")
		}
	}
	return b.String()
}

func TestSegmentCuts(t *testing.T) {
	if segmentCuts("short text") != nil {
		t.Fatal("short text cut")
	}
	text := longText(200_000)
	cuts := segmentCuts(text)
	if len(cuts) < 10 || cuts[len(cuts)-1] != len(text) {
		t.Fatalf("cuts %v", cuts)
	}
	for _, c := range cuts[:len(cuts)-1] {
		if text[c] != ' ' || text[c-1] <= ' ' || text[c+1] <= ' ' {
			t.Fatalf("cut at %d: %q", c, text[c-1:c+2])
		}
	}
	// Appending text keeps every earlier cut.
	more := segmentCuts(text + " and some more words at the end")
	if !reflect.DeepEqual(more[:len(cuts)-1], cuts[:len(cuts)-1]) {
		t.Fatal("appending moved earlier cuts")
	}
}

// Segmented tokens equal the whole text's, and a text that grows at its end
// tokenizes only its last segments again.
func TestSegmenterEncode(t *testing.T) {
	tok := &wordTokenizer{}
	var s segmenter
	text := longText(300_000)
	for range 3 {
		ids, offs, err := s.encode(tok, text)
		if err != nil {
			t.Fatal(err)
		}
		wantIDs, wantOffs, _ := (&wordTokenizer{}).EncodeOffsets(text)
		if !reflect.DeepEqual(ids, wantIDs) || !reflect.DeepEqual(offs, wantOffs) {
			t.Fatal("segmented tokens differ from the whole text's")
		}
		before := tok.bytes.Load()
		text += " another turn of the conversation"
		if _, _, err := s.encode(tok, text); err != nil {
			t.Fatal(err)
		}
		if got := tok.bytes.Load() - before; got > 2*segmentBytes+100 {
			t.Fatalf("tokenized %d bytes again for an appended turn", got)
		}
	}
}

// A tokenizer that does not split exactly tokenizes whole texts.
func TestSegmenterInexactTokenizer(t *testing.T) {
	tok := &wordTokenizer{joinSpaces: true}
	var s segmenter
	text := longText(100_000)
	ids, _, err := s.encode(tok, text)
	if err != nil {
		t.Fatal(err)
	}
	want, _, _ := (&wordTokenizer{joinSpaces: true}).EncodeOffsets(text)
	if s.exact || !reflect.DeepEqual(ids, want) {
		t.Fatalf("exact %v, tokens equal %v", s.exact, reflect.DeepEqual(ids, want))
	}
}

func TestSegmentCacheBound(t *testing.T) {
	c := newSegmentCache(10)
	for i := range 5 {
		c.put([32]byte{byte(i)}, segment{ids: make([]int64, 4)})
	}
	if c.tokens > 10 || c.ll.Len() != 2 {
		t.Fatalf("%d tokens in %d entries", c.tokens, c.ll.Len())
	}
	if _, ok := c.get([32]byte{4}); !ok {
		t.Fatal("newest entry evicted")
	}
}
