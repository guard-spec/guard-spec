// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/version"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// The shared layer of the scan cache (SCAN_CACHE_BACKEND=redis or postgres).
//
// The in-process cache (scan_cache.go) is per replica: after a restart, or
// when a load balancer sends the next turn of a session to another replica,
// every earlier tool result has to be classified again, within
// maxHistoryBytes, and a long session gets 413. A shared layer lets every
// replica reuse what any of them scored.
//
// What is stored: per entry, the detector's scores and verdict metadata of
// one text (inference.Scores, or an indirect.Verdict without the tool name)
// and the model identity they were computed with. Never the text, a tool name
// or anything else from the request: the key is a SHA-256.
//
// The key adds the model identity (sharedKey) to the in-process key (org,
// kind, source and the full content): the SHA-256 of the gateway binary, the
// models' files, their calibration and the detector configuration that
// changes a score (layers, fusion, L1 floor, cascade). Replicas that run
// different models or versions never read each other's entries, and a model
// reload needs no flush: the new identity has new keys, and the old entries
// expire.
//
// The shared layer is an optimization only. Each call is bounded by
// SCAN_CACHE_TIMEOUT; an error or a timeout counts as a miss (the text is
// scanned) or a lost write, never as a failed request.

// sharedStore is the shared layer: get returns the values it has of keys
// (missing keys are absent), set stores values for ttl. Every key of a call
// belongs to org.
type sharedStore interface {
	name() string
	get(ctx context.Context, org uuid.UUID, keys []string) (map[string][]byte, error)
	set(ctx context.Context, org uuid.UUID, entries map[string][]byte, ttl time.Duration) error
	close() error
}

// Values of SCAN_CACHE_BACKEND.
const (
	cacheBackendMemory   = "memory"
	cacheBackendRedis    = "redis"
	cacheBackendPostgres = "postgres"

	defaultScanCacheTimeout = 50 * time.Millisecond
)

// scanCacheConfig is SCAN_CACHE_BACKEND, SCAN_CACHE_REDIS_URL and
// SCAN_CACHE_TIMEOUT.
type scanCacheConfig struct {
	Backend  string
	RedisURL string
	Timeout  time.Duration
}

func loadScanCacheConfig(get func(string) string) (scanCacheConfig, error) {
	cfg := scanCacheConfig{
		Backend:  strings.ToLower(strings.TrimSpace(get("SCAN_CACHE_BACKEND"))),
		RedisURL: strings.TrimSpace(get("SCAN_CACHE_REDIS_URL")),
		Timeout:  defaultScanCacheTimeout,
	}
	switch cfg.Backend {
	case "":
		cfg.Backend = cacheBackendMemory
	case cacheBackendMemory, cacheBackendPostgres:
	case cacheBackendRedis:
		if cfg.RedisURL == "" {
			return cfg, errors.New("SCAN_CACHE_BACKEND=redis needs SCAN_CACHE_REDIS_URL (redis:// or rediss://)")
		}
		if _, err := redis.ParseURL(cfg.RedisURL); err != nil {
			// The error may quote the URL, password included.
			return cfg, errors.New("SCAN_CACHE_REDIS_URL is not a valid redis:// or rediss:// URL")
		}
	default:
		return cfg, errors.New("SCAN_CACHE_BACKEND must be memory, redis or postgres")
	}
	if v := strings.TrimSpace(get("SCAN_CACHE_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > 5*time.Second {
			return cfg, errors.New("SCAN_CACHE_TIMEOUT must be a duration from 1ms to 5s, such as 50ms")
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// openSharedStore returns the configured shared layer; nil for memory.
func openSharedStore(cfg scanCacheConfig, db *pgxpool.Pool) (sharedStore, error) {
	switch cfg.Backend {
	case cacheBackendRedis:
		return newRedisStore(cfg.RedisURL, cfg.Timeout)
	case cacheBackendPostgres:
		return pgStore{db: db}, nil
	}
	return nil, nil
}

// buildScanCache builds the scan cache of cfg: nil when SCAN_CACHE_SIZE is 0
// (every layer off), else the in-process layer with the shared one of
// SCAN_CACHE_BACKEND behind it. close frees the shared layer.
func buildScanCache(cfg config, db *pgxpool.Pool, live *ml.Live) (*scanCache, func(), error) {
	c := newScanCache(cfg.ScanCacheSize, scanCacheTTL)
	if c == nil {
		if cfg.ScanCache.Backend != cacheBackendMemory {
			slog.Warn("SCAN_CACHE_SIZE=0 turns the scan cache off, SCAN_CACHE_BACKEND included")
		}
		return nil, func() {}, nil
	}
	store, err := openSharedStore(cfg.ScanCache, db)
	if err != nil || store == nil {
		return c, func() {}, err
	}
	c.shared, c.timeout = store, cfg.ScanCache.Timeout
	c.identity = liveIdentity(live.Identity)
	c.identity() // start hashing the binary and the models now
	slog.Info("scan cache", "backend", store.name(), "size", cfg.ScanCacheSize,
		"timeout", cfg.ScanCache.Timeout.String(), "ttl", scanCacheTTL.String())
	return c, func() { _ = store.close() }, nil
}

// sharedKeyPrefix versions the shared key and value format.
const sharedKeyPrefix = "guardspec-scan-cache/v1"

// sharedKey derives the shared layer's key from the in-process key (which
// already covers org, kind, source and the full content) and the model
// identity.
func sharedKey(model, key string) string {
	h := sha256.New()
	for _, p := range []string{sharedKeyPrefix, model, key} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sharedEntry is what the shared layer stores for one key: the model identity
// and kind it was computed for (checked on read) and the value.
type sharedEntry struct {
	Model string          `json:"m"`
	Kind  string          `json:"k"`
	Value json.RawMessage `json:"v"`
}

// verdictValue is an indirect.Verdict with the scores its JSON leaves out.
type verdictValue struct {
	Verdict indirect.Verdict `json:"verdict"`
	Scores  inference.Scores `json:"scores"`
}

// encodeShared encodes a value of kind for the shared layer. A tool verdict
// loses its name (the caller has it), so nothing of the request is stored.
func encodeShared(model, kind string, val any) ([]byte, error) {
	var v any
	switch x := val.(type) {
	case inference.Scores:
		v = x
	case indirect.Verdict:
		v = verdictValue{Verdict: x, Scores: x.Scores}
	case indirect.ToolVerdict:
		v = verdictValue{Verdict: x.Verdict, Scores: x.Scores}
	default:
		return nil, fmt.Errorf("scan cache: cannot share a %T", val)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sharedEntry{Model: model, Kind: kind, Value: raw})
}

// decodeShared is the reverse of encodeShared; an entry of another model or
// kind is an error, which counts as a miss.
func decodeShared(model, kind string, b []byte) (any, error) {
	var e sharedEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if e.Model != model || e.Kind != kind {
		return nil, errors.New("scan cache: entry of another model or kind")
	}
	switch kind {
	case cacheDirect, cacheWindow:
		var s inference.Scores
		err := json.Unmarshal(e.Value, &s)
		return s, err
	case cacheSource, cacheTool:
		var v verdictValue
		if err := json.Unmarshal(e.Value, &v); err != nil {
			return nil, err
		}
		v.Verdict.Scores = v.Scores
		if kind == cacheTool {
			return indirect.ToolVerdict{Verdict: v.Verdict}, nil
		}
		return v.Verdict, nil
	}
	return nil, fmt.Errorf("scan cache: unknown kind %q", kind)
}

// cacheReq names one entry a request may need: its kind and in-process key.
type cacheReq struct{ kind, key string }

// cacheView is one request's view of the scan cache: what the layers had of
// the keys it asked for at the start, and what it scored since, written
// through at the end. A nil scanCache gives a view that always misses.
type cacheView struct {
	c     *scanCache
	gen   int64
	org   uuid.UUID
	model string // "": the shared layer is skipped
	hits  map[string]any
	puts  []cacheWrite
}

type cacheWrite struct {
	kind, key string
	val       any
}

// view looks reqs up: the in-process layer first, then the shared layer for
// the keys it lacks, in one call. A shared hit is copied into the
// in-process layer.
func (c *scanCache) view(ctx context.Context, gen int64, org uuid.UUID, reqs []cacheReq) *cacheView {
	v := &cacheView{c: c, gen: gen, org: org, hits: map[string]any{}}
	if c == nil {
		return v
	}
	var missing []cacheReq
	seen := map[string]bool{}
	for _, r := range reqs {
		if seen[r.key] {
			continue
		}
		seen[r.key] = true
		if val, ok := c.get(gen, r.key); ok {
			v.hits[r.key] = val
			metrics.ScanCacheLookups.WithLabelValues(cacheBackendMemory, "hit").Inc()
			continue
		}
		metrics.ScanCacheLookups.WithLabelValues(cacheBackendMemory, "miss").Inc()
		missing = append(missing, r)
	}
	if c.shared == nil || c.identity == nil {
		return v
	}
	model, ok := c.identity()
	if !ok {
		return v
	}
	v.model = model
	if len(missing) == 0 {
		return v
	}
	layer := c.shared.name()
	keys := make([]string, len(missing))
	for i, r := range missing {
		keys[i] = sharedKey(model, r.key)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	got, err := c.shared.get(ctx, org, keys)
	if err != nil {
		metrics.ScanCacheErrors.WithLabelValues(layer, "get").Inc()
		metrics.ScanCacheLookups.WithLabelValues(layer, "error").Add(float64(len(keys)))
		slog.Debug("shared scan cache read failed; scanning", "backend", layer, "err", err)
		return v
	}
	for i, r := range missing {
		b, ok := got[keys[i]]
		if !ok {
			metrics.ScanCacheLookups.WithLabelValues(layer, "miss").Inc()
			continue
		}
		val, err := decodeShared(model, r.kind, b)
		if err != nil {
			metrics.ScanCacheLookups.WithLabelValues(layer, "error").Inc()
			continue
		}
		metrics.ScanCacheLookups.WithLabelValues(layer, "hit").Inc()
		v.hits[r.key] = val
		c.put(gen, r.key, val)
	}
	return v
}

// get returns what the layers had of key when the view was made.
func (v *cacheView) get(key string) (any, bool) {
	val, ok := v.hits[key]
	return val, ok
}

// put stores a scored value in the in-process layer now, and queues it for
// the shared layer (flush).
func (v *cacheView) put(kind, key string, val any) {
	if v.c == nil {
		return
	}
	v.c.put(v.gen, key, val)
	v.hits[key] = val
	if v.model != "" {
		v.puts = append(v.puts, cacheWrite{kind: kind, key: key, val: val})
	}
}

// flush writes the queued values to the shared layer in one call, unless the
// models changed while the request was scanned (its scores may be of either).
func (v *cacheView) flush(ctx context.Context) {
	if v.c == nil || len(v.puts) == 0 {
		return
	}
	c := v.c
	defer func() { v.puts = nil }()
	if model, ok := c.identity(); !ok || model != v.model {
		return
	}
	layer := c.shared.name()
	entries := make(map[string][]byte, len(v.puts))
	for _, w := range v.puts {
		b, err := encodeShared(v.model, w.kind, w.val)
		if err != nil {
			slog.Warn("scan cache: value not shared", "kind", w.kind, "err", err)
			continue
		}
		entries[sharedKey(v.model, w.key)] = b
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.shared.set(ctx, v.org, entries, c.ttl); err != nil {
		metrics.ScanCacheErrors.WithLabelValues(layer, "set").Inc()
		slog.Debug("shared scan cache write failed", "backend", layer, "err", err)
	}
}

// redisStore keeps entries under guardspec:scan:<key> with EXPIRE.
type redisStore struct{ rdb *redis.Client }

const redisKeyPrefix = "guardspec:scan:"

func newRedisStore(url string, timeout time.Duration) (*redisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, errors.New("SCAN_CACHE_REDIS_URL is not a valid redis:// or rediss:// URL")
	}
	// The context of each call carries SCAN_CACHE_TIMEOUT; no retry fits in it.
	opt.ContextTimeoutEnabled = true
	opt.MaxRetries = -1
	opt.PoolTimeout = timeout
	opt.DisableIdentity = true // no CLIENT SETINFO on connect
	return &redisStore{rdb: redis.NewClient(opt)}, nil
}

func (r *redisStore) name() string { return cacheBackendRedis }

func (r *redisStore) get(ctx context.Context, _ uuid.UUID, keys []string) (map[string][]byte, error) {
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = redisKeyPrefix + k
	}
	vals, err := r.rdb.MGet(ctx, full...).Result()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(keys))
	for i, v := range vals {
		if s, ok := v.(string); ok {
			out[keys[i]] = []byte(s)
		}
	}
	return out, nil
}

func (r *redisStore) set(ctx context.Context, _ uuid.UUID, entries map[string][]byte, ttl time.Duration) error {
	_, err := r.rdb.Pipelined(ctx, func(p redis.Pipeliner) error {
		for k, v := range entries {
			p.Set(ctx, redisKeyPrefix+k, v, ttl)
		}
		return nil
	})
	return err
}

func (r *redisStore) close() error { return r.rdb.Close() }

// pgStore keeps entries in the scan_cache table (migration 020), which is
// row-level secured by org like every tenant table: each call sets app.org_id
// for its own transaction, so a replica serving one org can neither read nor
// overwrite another org's entries even with a key it should not know. Expired
// rows are never read and the control plane's retention job deletes them.
type pgStore struct{ db *pgxpool.Pool }

func (pgStore) name() string { return cacheBackendPostgres }

// The statements of a batch run in one implicit transaction, so the
// transaction-local app.org_id applies to the statement after it, in one
// round trip.
const (
	pgSetOrg       = `SELECT set_config('app.org_id', $1, true)`
	pgGetScanCache = `SELECT key, value FROM scan_cache WHERE key = ANY($1) AND expires_at > now()`
	pgSetScanCache = `INSERT INTO scan_cache (key, org_id, value, expires_at)
		SELECT k, $1, v::jsonb, now() + make_interval(secs => $4) FROM unnest($2::bytea[], $3::text[]) AS t(k, v)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`
)

func (s pgStore) get(ctx context.Context, org uuid.UUID, keys []string) (map[string][]byte, error) {
	raw := make([][]byte, len(keys))
	for i, k := range keys {
		b, err := hex.DecodeString(k)
		if err != nil {
			return nil, err
		}
		raw[i] = b
	}
	b := &pgx.Batch{}
	b.Queue(pgSetOrg, org.String())
	b.Queue(pgGetScanCache, raw)
	res := s.db.SendBatch(ctx, b)
	defer func() { _ = res.Close() }()
	if _, err := res.Exec(); err != nil {
		return nil, err
	}
	rows, err := res.Query()
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for rows.Next() {
		var k, v []byte
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		out[hex.EncodeToString(k)] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, res.Close()
}

func (s pgStore) set(ctx context.Context, org uuid.UUID, entries map[string][]byte, ttl time.Duration) error {
	keys, vals := make([][]byte, 0, len(entries)), make([]string, 0, len(entries))
	for k, v := range entries {
		b, err := hex.DecodeString(k)
		if err != nil {
			return err
		}
		keys, vals = append(keys, b), append(vals, string(v))
	}
	b := &pgx.Batch{}
	b.Queue(pgSetOrg, org.String())
	b.Queue(pgSetScanCache, org, keys, vals, ttl.Seconds())
	return s.db.SendBatch(ctx, b).Close()
}

func (pgStore) close() error { return nil }

// binaryIdentity hashes the running gateway binary: the detector's code (L1
// rules, sanitizer, built-in calibrations and exemplars) is part of what a
// score depends on. Replicas of one image share it. When the binary cannot be
// read, the version string stands in.
var binaryIdentity = sync.OnceValue(func() string {
	h := sha256.New()
	h.Write([]byte(version.String() + "\x00"))
	exe, err := os.Executable()
	if err == nil {
		var f *os.File
		if f, err = os.Open(exe); err == nil {
			_, err = io.Copy(h, f)
			_ = f.Close()
		}
	}
	if err != nil {
		slog.Warn("scan cache: the gateway binary could not be hashed; the shared cache keys on the version only", "err", err)
	}
	return hex.EncodeToString(h.Sum(nil))
})

// liveIdentity is the identity the shared layer keys on: the binary's and
// the running models' (ml.Live.Identity). Both are computed in the
// background; until then the shared layer is skipped.
func liveIdentity(models func() (string, bool)) func() (string, bool) {
	var started sync.Once
	var bin atomic.Pointer[string]
	return func() (string, bool) {
		started.Do(func() {
			go func() {
				id := binaryIdentity()
				bin.Store(&id)
			}()
		})
		m, ok := models() // first, so that the first call starts both
		b := bin.Load()
		if !ok || b == nil {
			return "", false
		}
		sum := sha256.Sum256([]byte(*b + "\x00" + m))
		return hex.EncodeToString(sum[:]), true
	}
}
