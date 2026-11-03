// Package ratelimit is an in-memory token bucket limiter keyed by API key.
//
// State lives in the process, so each gateway replica enforces the limits on
// its own: with N replicas behind a load balancer a key can make up to N times
// its limit in total. A shared store (Redis, Postgres) would be needed for a
// global limit.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limits are per minute. Zero means unlimited.
type Limits struct {
	RPM int64 // requests per minute
	TPM int64 // tokens per minute
}

// Unlimited reports whether neither limit applies.
func (l Limits) Unlimited() bool { return l.RPM <= 0 && l.TPM <= 0 }

// Which limit refused a request.
const (
	LimitRequests = "requests"
	LimitTokens   = "tokens"
)

// Decision is the outcome of Allow.
type Decision struct {
	Allowed    bool
	Limit      string        // LimitRequests or LimitTokens when refused
	RetryAfter time.Duration // when refused: how long until the request would pass
}

// bucket holds up to capacity tokens and refills at capacity per minute.
type bucket struct {
	capacity float64
	tokens   float64
	last     time.Time
}

func (b *bucket) refill(now time.Time, capacity float64) {
	if b.capacity != capacity {
		// New bucket, or the limit changed: keep what was used, so raising a
		// limit frees the difference at once.
		b.tokens = math.Max(b.tokens+capacity-b.capacity, 0)
		b.capacity = capacity
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Minutes() * capacity
		b.last = now
	}
	b.tokens = math.Min(b.tokens, capacity)
}

// wait is how long until cost tokens are available.
func (b *bucket) wait(cost float64) time.Duration {
	if b.tokens >= cost {
		return 0
	}
	return time.Duration((cost - b.tokens) / b.capacity * float64(time.Minute))
}

type entry struct {
	req, tok bucket
	seen     time.Time
}

// idleTTL is how long an unused key keeps its state. After a minute without
// requests both buckets are full again, so dropping the state changes nothing.
const idleTTL = 2 * time.Minute

// Limiter is safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	keys      map[string]*entry
	now       func() time.Time
	lastSweep time.Time
}

// New returns an empty limiter.
func New() *Limiter {
	return &Limiter{keys: map[string]*entry{}, now: time.Now}
}

// Allow takes one request and cost tokens from key's buckets, or nothing if
// either bucket is short. A cost above the token limit is capped at the limit,
// so one large request can still pass once the bucket is full.
func (l *Limiter) Allow(key string, lim Limits, cost int64) Decision {
	if lim.Unlimited() {
		return Decision{Allowed: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	e := l.keys[key]
	if e == nil {
		e = &entry{req: bucket{last: now}, tok: bucket{last: now}}
		l.keys[key] = e
	}
	e.seen = now

	var reqWait, tokWait time.Duration
	tokCost := 0.0
	if lim.RPM > 0 {
		e.req.refill(now, float64(lim.RPM))
		reqWait = e.req.wait(1)
	}
	if lim.TPM > 0 {
		e.tok.refill(now, float64(lim.TPM))
		tokCost = math.Min(float64(max(cost, 0)), float64(lim.TPM))
		tokWait = e.tok.wait(tokCost)
	}
	switch {
	case reqWait > 0 && reqWait >= tokWait:
		return Decision{Limit: LimitRequests, RetryAfter: reqWait}
	case tokWait > 0:
		return Decision{Limit: LimitTokens, RetryAfter: tokWait}
	}
	if lim.RPM > 0 {
		e.req.tokens--
	}
	if lim.TPM > 0 {
		e.tok.tokens -= tokCost
	}
	return Decision{Allowed: true}
}

// sweep drops idle keys, at most once per idleTTL. Callers hold mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < idleTTL {
		return
	}
	l.lastSweep = now
	for k, e := range l.keys {
		if now.Sub(e.seen) > idleTTL {
			delete(l.keys, k)
		}
	}
}

// Len returns the number of keys with state. Tests use it.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}
