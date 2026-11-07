// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/retention"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Shared scan cache backends against a real Redis (or Valkey) and Postgres.
// TEST_REDIS_URL names a throwaway Redis; the test is skipped without it.
// Postgres is the compose stack's, or TEST_DATABASE_URL (application role)
// and TEST_OWNER_DATABASE_URL (the owner, to look past row level security).

func testRedisURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	return url
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func appPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	db, err := pgxpool.New(context.Background(),
		envOrDefault("TEST_DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func ownerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	db, err := pgxpool.New(context.Background(),
		envOrDefault("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// redisValues returns every scan cache value in rdb with its remaining TTL.
func redisValues(t *testing.T, rdb *redis.Client) ([][]byte, []time.Duration) {
	t.Helper()
	ctx := context.Background()
	var vals [][]byte
	var ttls []time.Duration
	iter := rdb.Scan(ctx, 0, redisKeyPrefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		v, err := rdb.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		ttl, err := rdb.PTTL(ctx, iter.Val()).Result()
		if err != nil {
			t.Fatal(err)
		}
		vals, ttls = append(vals, v), append(ttls, ttl)
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	return vals, ttls
}

func clearRedis(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx := context.Background()
	iter := rdb.Scan(ctx, 0, redisKeyPrefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		rdb.Del(ctx, iter.Val())
	}
}

func TestRedisScanCache(t *testing.T) {
	url := testRedisURL(t)
	ctx := context.Background()
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()
	clearRedis(t, rdb)
	t.Cleanup(func() { clearRedis(t, rdb) })

	s, err := newRedisStore(url, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	org := uuid.New()
	key := sharedKey("m", cacheKey(org, cacheDirect, "system", "x"))
	if err := s.set(ctx, org, map[string][]byte{key: []byte(`{"m":"m"}`)}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := s.get(ctx, org, []string{key, sharedKey("m", "absent")})
	if err != nil || string(got[key]) != `{"m":"m"}` || len(got) != 1 {
		t.Fatalf("get %q %v", got, err)
	}
	// EXPIRE: the entry is gone after its TTL.
	if ttl := rdb.PTTL(ctx, redisKeyPrefix+key).Val(); ttl <= 0 || ttl > 2*time.Second {
		t.Errorf("PTTL %v", ttl)
	}
	time.Sleep(2100 * time.Millisecond)
	if got, err := s.get(ctx, org, []string{key}); err != nil || len(got) != 0 {
		t.Errorf("expired entry: %q %v", got, err)
	}

	// A wrong password (when the server requires one; CI's has none), or
	// nothing listening: errors, which the cache turns into misses
	// (TestSharedCacheFallback).
	if opt.Password != "" {
		bad := *opt
		bad.Password = "wrong-password"
		wrong := &redisStore{rdb: redis.NewClient(&bad)}
		defer wrong.close()
		if _, err := wrong.get(ctx, org, []string{key}); err == nil {
			t.Error("wrong password accepted")
		}
	}
	down, _ := newRedisStore("redis://127.0.0.1:1/0", 50*time.Millisecond)
	defer down.close()
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	start := time.Now()
	if _, err := down.get(tctx, org, []string{key}); err == nil {
		t.Error("no server, no error")
	}
	cancel()
	if d := time.Since(start); d > time.Second {
		t.Errorf("unreachable redis took %v", d)
	}

	// Two replicas, each its own client, as two processes would have.
	clearRedis(t, rdb)
	run := runReplicaSession(t, func() sharedStore {
		s, err := newRedisStore(url, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.close() })
		return s
	}, sessionTurns)
	checkSharedSession(t, run)
	vals, ttls := redisValues(t, rdb)
	assertNoText(t, vals)
	for _, ttl := range ttls {
		if ttl <= scanCacheTTL-5*time.Minute || ttl > scanCacheTTL {
			t.Fatalf("entry TTL %v, want about %v", ttl, scanCacheTTL)
		}
	}
	t.Logf("redis: %d entries, every value scores and metadata only, such as %s", len(vals), vals[0])
}

func TestPostgresScanCache(t *testing.T) {
	ctx := context.Background()
	db, owner := appPool(t), ownerPool(t)
	wipe := func() {
		if _, err := owner.Exec(ctx, `DELETE FROM scan_cache`); err != nil {
			t.Fatal(err)
		}
	}
	wipe()
	t.Cleanup(wipe)

	other := uuid.New()
	err := tenant.WithOrg(ctx, db, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'scan cache', $2)`, other, other.String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, other) })

	s := pgStore{db: db}
	key := sharedKey("m", cacheKey(devOrg, cacheDirect, "system", "x"))
	val := []byte(`{"k": "direct", "m": "m", "v": {}}`)
	if err := s.set(ctx, devOrg, map[string][]byte{key: val}, scanCacheTTL); err != nil {
		t.Fatal(err)
	}
	// Upsert: a second write of the key replaces it.
	if err := s.set(ctx, devOrg, map[string][]byte{key: val}, scanCacheTTL); err != nil {
		t.Fatal(err)
	}
	got, err := s.get(ctx, devOrg, []string{key, sharedKey("m", "absent")})
	if err != nil || len(got) != 1 || !strings.Contains(string(got[key]), `"direct"`) {
		t.Fatalf("get %q %v", got, err)
	}
	var secs float64
	if err := owner.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM expires_at - now())::float8 FROM scan_cache WHERE key = decode($1, 'hex')`, key).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	left := time.Duration(secs * float64(time.Second))
	if left <= scanCacheTTL-time.Minute || left > scanCacheTTL {
		t.Errorf("expires in %v, want %v", left, scanCacheTTL)
	}

	// Row level security: another org reads nothing, even with the key, and
	// cannot overwrite the row.
	if got, err := s.get(ctx, other, []string{key}); err != nil || len(got) != 0 {
		t.Errorf("another org read %q %v", got, err)
	}
	if err := s.set(ctx, other, map[string][]byte{key: []byte(`{"m":"poisoned"}`)}, scanCacheTTL); err == nil {
		t.Error("another org overwrote the row")
	}
	if got, _ := s.get(ctx, devOrg, []string{key}); strings.Contains(string(got[key]), "poisoned") {
		t.Error("row overwritten")
	}
	// Without app.org_id the application role sees no row.
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM scan_cache`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows without an org: %d %v", n, err)
	}

	// Expired rows are not read, and the retention job deletes them.
	expired := sharedKey("m", "expired")
	if err := s.set(ctx, devOrg, map[string][]byte{expired: val}, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got, _ := s.get(ctx, devOrg, []string{expired}); len(got) != 0 {
		t.Error("expired row read")
	}
	res, err := retention.Once(ctx, db, retention.Config{ScanCache: true, Batch: 100}, time.Now())
	if err != nil || res.ScanCacheDeleted < 1 {
		t.Errorf("retention: %+v %v", res, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM scan_cache WHERE key = decode($1, 'hex')`, expired).Scan(&n); err != nil || n != 0 {
		t.Errorf("expired row kept: %d %v", n, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM scan_cache WHERE key = decode($1, 'hex')`, key).Scan(&n); err != nil || n != 1 {
		t.Errorf("live row purged: %d %v", n, err)
	}

	// A cancelled context is an error, not a hang.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.get(cctx, devOrg, []string{key}); err == nil {
		t.Error("cancelled get succeeded")
	}

	// The scan cache end to end, through the view: scores of every kind.
	wipe()
	c := sharedCache(s, "pg-model", 2*time.Second)
	scores := inference.Scores{Injection: inference.Score{Label: "BENIGN", Confidence: 0.25}}
	k := cacheKey(devOrg, cacheDirect, "system", "hello")
	v := c.view(ctx, 1, devOrg, []cacheReq{{cacheDirect, k}})
	v.put(cacheDirect, k, scores)
	v.flush(ctx)
	if got, ok := sharedCache(s, "pg-model", 2*time.Second).view(ctx, 1, devOrg, []cacheReq{{cacheDirect, k}}).get(k); !ok ||
		got.(inference.Scores).Injection.Confidence != 0.25 {
		t.Errorf("view through postgres: %v %v", got, ok)
	}

	// Two replicas, each its own pool, as two processes would have.
	wipe()
	run := runReplicaSession(t, func() sharedStore {
		return pgStore{db: appPool(t)}
	}, sessionTurns)
	checkSharedSession(t, run)
	rows, err := owner.Query(ctx, `SELECT value::text, org_id FROM scan_cache`)
	if err != nil {
		t.Fatal(err)
	}
	var vals [][]byte
	for rows.Next() {
		var v string
		var org uuid.UUID
		if err := rows.Scan(&v, &org); err != nil {
			t.Fatal(err)
		}
		if org != devOrg {
			t.Errorf("row of org %s", org)
		}
		vals = append(vals, []byte(v))
	}
	rows.Close()
	assertNoText(t, vals)
	t.Logf("postgres: %d rows, every value scores and metadata only, such as %s", len(vals), vals[0])
}
