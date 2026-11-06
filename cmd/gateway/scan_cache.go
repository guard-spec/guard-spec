// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	"github.com/google/uuid"
)

// scanCache keeps detector results of texts that come back unchanged in
// every request of a session: Claude Code resends its system prompt, its tool
// list and every earlier tool result each turn. It is a small LRU in this
// process, keyed on the org (per-org exemplars change scores), a kind and the
// SHA-256 of the full content. It is cleared when the models change (the
// live detector's generation), and entries expire after scanCacheTTL, which
// bounds how long a cached score ignores a new org exemplar (L3). It holds
// scores and hashes, never text.
type scanCache struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	gen   int64
	ll    *list.List // front: most recently used
	items map[string]*list.Element
}

type cacheEntry struct {
	key string
	val any
	at  time.Time
}

const (
	defaultScanCacheSize = 4096
	scanCacheTTL         = 6 * time.Hour
)

// newScanCache returns a cache of max entries; nil when max is 0 (off).
func newScanCache(max int, ttl time.Duration) *scanCache {
	if max <= 0 {
		return nil
	}
	return &scanCache{max: max, ttl: ttl, now: time.Now, ll: list.New(), items: map[string]*list.Element{}}
}

// cacheKey hashes the org, the kind and each part, length-prefixed so that
// parts cannot run into each other.
func cacheKey(org uuid.UUID, kind string, parts ...string) string {
	h := sha256.New()
	h.Write(org[:])
	var n [8]byte
	for _, p := range append([]string{kind}, parts...) {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sync clears the cache when the models changed; the caller holds mu.
func (c *scanCache) sync(gen int64) {
	if gen != c.gen {
		c.gen = gen
		c.ll.Init()
		clear(c.items)
	}
}

func (c *scanCache) get(gen int64, key string) (any, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sync(gen)
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if c.now().Sub(e.at) > c.ttl {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.val, true
}

func (c *scanCache) put(gen int64, key string, val any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sync(gen)
	if el, ok := c.items[key]; ok {
		el.Value = &cacheEntry{key: key, val: val, at: c.now()}
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&cacheEntry{key: key, val: val, at: c.now()})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*cacheEntry).key)
	}
}

// len is the number of entries, for tests.
func (c *scanCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// generation is the live detector's generation, 0 without one.
func (gw gateway) generation() int64 {
	if gw.live == nil {
		return 0
	}
	return gw.live.Generation()
}
