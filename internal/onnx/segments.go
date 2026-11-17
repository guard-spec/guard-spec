// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"container/list"
	"crypto/sha256"
	"slices"
	"sync"
)

// A long text is tokenized in segments, each looked up in a cache of its own
// tokens: a chat whose context grows turn by turn resends the same text with
// a little more at its end, and only the new end is tokenized again
// (tokenizing 800 KB takes about 150 ms of CPU, more than scoring the one new
// window).
//
// The result is exactly the tokenization of the whole text. A segment ends at
// a single space between two bytes that are not whitespace or control
// characters: for the classifiers' tokenizers (SentencePiece with a
// Metaspace pre-tokenizer, WordPiece with a whitespace pre-tokenizer) the
// tokens of text are then the tokens of the part before the space followed by
// those of the rest, the space included. A model checks this once on a
// sample (splitExact) and tokenizes whole texts when it does not hold. Cut
// points depend only on the text before them, so text appended at the end
// leaves every earlier segment as it was.

const (
	// segmentBytes is the length a segment reaches before it is cut at the
	// next split point.
	segmentBytes = 16 << 10
	// segmentCacheTokens bounds the tokens the cache holds, per model (16
	// bytes a token: about 16 MiB).
	segmentCacheTokens = 1 << 20
)

// segmentCuts returns the byte offsets where text's segments end, the last
// being len(text); nil when text is one segment.
func segmentCuts(text string) []int {
	if len(text) <= segmentBytes {
		return nil
	}
	var cuts []int
	for p := segmentBytes; p < len(text)-1; p++ {
		if text[p] == ' ' && text[p-1] > ' ' && text[p+1] > ' ' {
			cuts = append(cuts, p)
			p += segmentBytes - 1
		}
	}
	return append(cuts, len(text))
}

// segment is the tokens of one segment, offsets relative to its start.
type segment struct {
	ids  []int64
	offs [][2]int32
}

// segmentCache is an LRU of segments by the SHA-256 of their text.
type segmentCache struct {
	mu     sync.Mutex
	max    int // tokens
	tokens int
	ll     *list.List
	items  map[[sha256.Size]byte]*list.Element
}

type segmentEntry struct {
	key [sha256.Size]byte
	seg segment
}

func newSegmentCache(maxTokens int) *segmentCache {
	return &segmentCache{max: maxTokens, ll: list.New(), items: map[[sha256.Size]byte]*list.Element{}}
}

func (c *segmentCache) get(k [sha256.Size]byte) (segment, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return segment{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*segmentEntry).seg, true
}

func (c *segmentCache) put(k [sha256.Size]byte, s segment) {
	if len(s.ids) > c.max {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[k]; ok {
		return
	}
	c.items[k] = c.ll.PushFront(&segmentEntry{key: k, seg: s})
	c.tokens += len(s.ids)
	for c.tokens > c.max {
		last := c.ll.Back()
		e := last.Value.(*segmentEntry)
		c.ll.Remove(last)
		delete(c.items, e.key)
		c.tokens -= len(e.seg.ids)
	}
}

// splitSample is text with the cases a tokenizer could join across a space:
// words, numbers, punctuation, Vietnamese, CJK, emoji and code.
const splitSample = "The quarterly report shows 12.5% growth. Dữ liệu tiếng Việt có dấu, " +
	"không dấu va teencode ko bik. 東京の天気 😀 emoji, func main() { x := a+b } " +
	"https://example.com/a?b=c don't re-run it's café naïve 1,000 $5 #tag @user"

// splitExact reports whether tokenizing splitSample in two at each of its
// split points gives the tokens of the whole sample.
func splitExact(ot offsetTokenizer) bool {
	whole, _, err := ot.EncodeOffsets(splitSample)
	if err != nil {
		return false
	}
	s := splitSample
	for p := 1; p < len(s)-1; p++ {
		if s[p] != ' ' || s[p-1] <= ' ' || s[p+1] <= ' ' {
			continue
		}
		a, _, err1 := ot.EncodeOffsets(s[:p])
		b, _, err2 := ot.EncodeOffsets(s[p:])
		if err1 != nil || err2 != nil || !slices.Equal(whole, append(a, b...)) {
			return false
		}
	}
	return true
}

// segmenter tokenizes long texts of one model in cached segments.
type segmenter struct {
	once  sync.Once
	exact bool
	cache *segmentCache
}

// encode returns the tokens and byte offsets of text, as ot.EncodeOffsets
// would, from cached segments when the tokenizer splits exactly.
func (s *segmenter) encode(ot offsetTokenizer, text string) ([]int64, [][2]int, error) {
	cuts := segmentCuts(text)
	if cuts == nil {
		return ot.EncodeOffsets(text)
	}
	s.once.Do(func() {
		s.exact = splitExact(ot)
		s.cache = newSegmentCache(segmentCacheTokens)
	})
	if !s.exact {
		return ot.EncodeOffsets(text)
	}
	var ids []int64
	var offs [][2]int
	start := 0
	for _, end := range cuts {
		part := text[start:end]
		k := sha256.Sum256([]byte(part))
		seg, ok := s.cache.get(k)
		if !ok {
			pi, po, err := ot.EncodeOffsets(part)
			if err != nil {
				return nil, nil, err
			}
			seg = segment{ids: pi, offs: make([][2]int32, len(po))}
			for i, o := range po {
				seg.offs[i] = [2]int32{int32(o[0]), int32(o[1])}
			}
			s.cache.put(k, seg)
		}
		ids = append(ids, seg.ids...)
		for _, o := range seg.offs {
			offs = append(offs, [2]int{start + int(o[0]), start + int(o[1])})
		}
		start = end
	}
	return ids, offs, nil
}
