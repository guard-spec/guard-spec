// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// The chunk kind of the scan cache: the fused result of one token window of
// the long path (inference.WindowCache), before any per-source adjustment
// and before the long document rule, which every request applies again. A
// chat whose context grows turn by turn, or a document edited near its end,
// keeps the windows it had, and only the new ones are scored.
//
// The key is the org, the kind and the window's key (ml.ScoreLong: its token
// ids and text, versioned); the shared layer adds the model identity, which
// covers the tokenizer and the classifier. The long path leaves L3 (the
// org's exemplars) out, so an entry does not go stale when they change.
//
// Chunk entries have an in-process LRU of their own (chunkCacheFactor times
// SCAN_CACHE_SIZE entries), so one long document does not push a session's
// other entries out.
const cacheChunk = "chunk"

const (
	// chunkCacheFactor sizes the chunk LRU: a 200k-token text has about
	// 1,000 windows.
	chunkCacheFactor = 8
	// maxChunkKeys bounds the windows of one call looked up or stored, and
	// with it the size of one shared-layer call.
	maxChunkKeys = 8192
)

// chunkCache is the WindowCache of one request: its org, at the models'
// generation when the request was admitted.
type chunkCache struct {
	c   *scanCache
	gen int64
	org uuid.UUID
}

// windowCache returns the WindowCache of a request; nil when the request does
// not use the scan cache or it is off.
func (gw gateway) windowCache(g *textGuard) inference.WindowCache {
	if gw.cache == nil || gw.cache.chunks == nil || g == nil || !g.useCache {
		return nil
	}
	return chunkCache{c: gw.cache.chunks, gen: gw.generation(), org: g.org}
}

func (cc chunkCache) key(k string) string { return cacheKey(cc.org, cacheChunk, k) }

func (cc chunkCache) Lookup(ctx context.Context, keys []string) map[string]fusion.Result {
	keys = keys[:min(len(keys), maxChunkKeys)]
	reqs := make([]cacheReq, len(keys))
	for i, k := range keys {
		reqs[i] = cacheReq{cacheChunk, cc.key(k)}
	}
	v := cc.c.view(ctx, cc.gen, cc.org, reqs)
	out := make(map[string]fusion.Result, len(keys))
	for i, k := range keys {
		if hit, ok := v.get(reqs[i].key); ok {
			if r, ok := hit.(fusion.Result); ok {
				out[k] = r
			}
		}
	}
	return out
}

func (cc chunkCache) Store(ctx context.Context, results map[string]fusion.Result) {
	v := cc.c.view(ctx, cc.gen, cc.org, nil)
	n := 0
	for k, r := range results {
		if n == maxChunkKeys {
			break
		}
		v.put(cacheChunk, cc.key(k), r)
		n++
	}
	v.flush(ctx)
}

// configIdentity is the gateway configuration a cached verdict depends on
// that the models' identity (ml.Live.Identity) does not cover:
// TOOL_CODE_CORROBORATION changes a tool result's verdict.
func configIdentity(cfg config) string {
	if cfg.Scan.NoCodeCorroboration {
		return "code_corroboration=off"
	}
	return "code_corroboration=on"
}
