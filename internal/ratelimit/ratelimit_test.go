package ratelimit

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestLimiter() (*Limiter, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := New()
	l.now = c.now
	return l, c
}

func TestRequestsPerMinute(t *testing.T) {
	l, c := newTestLimiter()
	lim := Limits{RPM: 2}
	for i := range 2 {
		if d := l.Allow("k", lim, 0); !d.Allowed {
			t.Fatalf("request %d refused", i)
		}
	}
	d := l.Allow("k", lim, 0)
	if d.Allowed || d.Limit != LimitRequests {
		t.Fatalf("third request: %+v, want refused by requests", d)
	}
	if d.RetryAfter != 30*time.Second {
		t.Errorf("retry after %v, want 30s (one request refills in 60s/2)", d.RetryAfter)
	}
	// Another key has its own bucket.
	if d := l.Allow("other", lim, 0); !d.Allowed {
		t.Error("other key refused")
	}
	c.advance(30 * time.Second)
	if d := l.Allow("k", lim, 0); !d.Allowed {
		t.Errorf("after refill: %+v", d)
	}
	if d := l.Allow("k", lim, 0); d.Allowed {
		t.Error("bucket should be empty again")
	}
}

func TestTokensPerMinute(t *testing.T) {
	l, c := newTestLimiter()
	lim := Limits{TPM: 1000}
	if d := l.Allow("k", lim, 800); !d.Allowed {
		t.Fatal("first request refused")
	}
	d := l.Allow("k", lim, 400)
	if d.Allowed || d.Limit != LimitTokens {
		t.Fatalf("over the token limit: %+v", d)
	}
	if want := 12 * time.Second; d.RetryAfter != want { // 200 tokens short at 1000/min
		t.Errorf("retry after %v, want %v", d.RetryAfter, want)
	}
	// A refused request takes nothing.
	c.advance(12 * time.Second)
	if d := l.Allow("k", lim, 400); !d.Allowed {
		t.Errorf("after refill: %+v", d)
	}
}

func TestLargeRequestIsCappedAtTheLimit(t *testing.T) {
	l, _ := newTestLimiter()
	lim := Limits{TPM: 100}
	if d := l.Allow("k", lim, 10_000); !d.Allowed {
		t.Fatal("a request larger than the limit must pass on a full bucket")
	}
	if d := l.Allow("k", lim, 1); d.Allowed {
		t.Error("bucket should be empty")
	}
}

func TestBothLimitsMustPass(t *testing.T) {
	l, _ := newTestLimiter()
	lim := Limits{RPM: 10, TPM: 100}
	if d := l.Allow("k", lim, 100); !d.Allowed {
		t.Fatal(d)
	}
	if d := l.Allow("k", lim, 50); d.Allowed || d.Limit != LimitTokens {
		t.Fatalf("got %+v, want refused by tokens", d)
	}
	// The refused request did not take a request token either: 9 more fit.
	for i := range 9 {
		if d := l.Allow("k", lim, 0); !d.Allowed {
			t.Fatalf("request %d refused: %+v", i, d)
		}
	}
	if d := l.Allow("k", lim, 0); d.Allowed || d.Limit != LimitRequests {
		t.Fatalf("got %+v, want refused by requests", d)
	}
}

func TestUnlimited(t *testing.T) {
	l, _ := newTestLimiter()
	for range 1000 {
		if d := l.Allow("k", Limits{}, 1_000_000); !d.Allowed {
			t.Fatal("unlimited key refused")
		}
	}
	if l.Len() != 0 {
		t.Error("unlimited keys should keep no state")
	}
}

func TestLimitChange(t *testing.T) {
	l, _ := newTestLimiter()
	if d := l.Allow("k", Limits{RPM: 1}, 0); !d.Allowed {
		t.Fatal(d)
	}
	if d := l.Allow("k", Limits{RPM: 1}, 0); d.Allowed {
		t.Fatal("limit 1 should refuse the second request")
	}
	// Raising the limit keeps what was used: 1 of 3.
	for i := range 2 {
		if d := l.Allow("k", Limits{RPM: 3}, 0); !d.Allowed {
			t.Fatalf("request %d after raise refused", i)
		}
	}
	if d := l.Allow("k", Limits{RPM: 3}, 0); d.Allowed {
		t.Error("raised limit exceeded")
	}
}

func TestIdleKeysAreDropped(t *testing.T) {
	l, c := newTestLimiter()
	l.Allow("a", Limits{RPM: 1}, 0)
	c.advance(idleTTL + time.Second)
	l.Allow("b", Limits{RPM: 1}, 0)
	if l.Len() != 1 {
		t.Errorf("keys = %d, want 1 after the sweep", l.Len())
	}
}
