// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// bucket is a token bucket: it holds up to burst tokens and gains rate
// tokens per second.
type bucket struct {
	tokens float64
	last   time.Time
}

// take refills b to now and takes one token. When none is left it returns
// how long until one is.
func (b *bucket) take(now time.Time, burst, rate float64) (bool, time.Duration) {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// full reports whether b would be full at now (an idle client).
func (b *bucket) full(now time.Time, burst, rate float64) bool {
	return b.tokens+now.Sub(b.last).Seconds()*rate >= burst
}

// limiter keeps two token buckets per client (per minute and per day) and
// one for all clients together. Client keys are IPv4 addresses and IPv6 /64
// prefixes, so one IPv6 host cannot rotate through its own addresses.
type limiter struct {
	mu         sync.Mutex
	perMin     float64 // burst of the minute bucket
	perDay     float64
	globalMin  float64
	maxTracked int
	clients    map[netip.Addr]*clientBuckets
	global     bucket
	now        func() time.Time
}

type clientBuckets struct{ minute, day bucket }

// verdict of limiter.allow.
type verdict int

const (
	allowed verdict = iota
	limited         // this client is over its limit: 429
	busy            // the service as a whole is over its limit: 503
)

func newLimiter(perMin, perDay, globalMin, maxTracked int) *limiter {
	return &limiter{
		perMin: float64(perMin), perDay: float64(perDay), globalMin: float64(globalMin),
		maxTracked: maxTracked, clients: map[netip.Addr]*clientBuckets{}, now: time.Now,
	}
}

// clientKey is the limiter key of an address: IPv4 as is, IPv6 as its /64.
func clientKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// allow takes a token for the client and one from the global bucket. A
// client over its limit does not use up global tokens.
func (l *limiter) allow(client netip.Addr) (verdict, time.Duration) {
	key := clientKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	c := l.clients[key]
	if c == nil {
		if len(l.clients) >= l.maxTracked {
			l.sweepLocked(now)
			if len(l.clients) >= l.maxTracked {
				return busy, time.Minute
			}
		}
		c = &clientBuckets{}
		l.clients[key] = c
	}
	// Check both client buckets before taking from either, so a refused
	// request costs nothing.
	minRate, dayRate := l.perMin/60, l.perDay/86400
	m, d := c.minute, c.day
	okMin, waitMin := m.take(now, l.perMin, minRate)
	okDay, waitDay := d.take(now, l.perDay, dayRate)
	if !okMin || !okDay {
		// Keep the refill bookkeeping but give back what was taken.
		if okMin {
			m.tokens++
		}
		if okDay {
			d.tokens++
		}
		c.minute, c.day = m, d
		return limited, max(waitMin, waitDay)
	}
	g := l.global
	if ok, wait := g.take(now, l.globalMin, l.globalMin/60); !ok {
		l.global = g
		return busy, wait
	}
	l.global, c.minute, c.day = g, m, d
	return allowed, 0
}

// sweep drops clients whose buckets are full again: they are idle, and a
// new entry would start full anyway.
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.now())
}

func (l *limiter) sweepLocked(now time.Time) {
	for k, c := range l.clients {
		if c.minute.full(now, l.perMin, l.perMin/60) && c.day.full(now, l.perDay, l.perDay/86400) {
			delete(l.clients, k)
		}
	}
}

func (l *limiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}
