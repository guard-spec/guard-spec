// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

// Clean is a pure function of its input, and a chat client resends the same
// large messages (a pasted document, an earlier tool result) on every turn:
// cleaning 800 KB takes about 90 ms. Results of large inputs are kept in a
// small LRU by the SHA-256 of the input, bounded by the bytes it holds.

const (
	// cleanCacheMin is the smallest input whose result is cached.
	cleanCacheMin = 32 << 10
	// cleanCacheBytes bounds the bytes of the cached results (both views).
	cleanCacheBytes = 32 << 20
)

type cleanEntry struct {
	key [sha256.Size]byte
	res Result
}

type cleanCache struct {
	mu    sync.Mutex
	bytes int
	ll    *list.List
	items map[[sha256.Size]byte]*list.Element
}

var cleaned = &cleanCache{ll: list.New(), items: map[[sha256.Size]byte]*list.Element{}}

func resultBytes(r Result) int { return len(r.Scan) + len(r.Forward) }

func (c *cleanCache) get(k [sha256.Size]byte) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return Result{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*cleanEntry).res, true
}

func (c *cleanCache) put(k [sha256.Size]byte, r Result) {
	n := resultBytes(r)
	if n > cleanCacheBytes/4 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[k]; ok {
		return
	}
	c.items[k] = c.ll.PushFront(&cleanEntry{key: k, res: r})
	c.bytes += n
	for c.bytes > cleanCacheBytes {
		last := c.ll.Back()
		e := last.Value.(*cleanEntry)
		c.ll.Remove(last)
		delete(c.items, e.key)
		c.bytes -= resultBytes(e.res)
	}
}
