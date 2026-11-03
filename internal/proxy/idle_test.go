package proxy

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func idleResponse(idle time.Duration) (*Response, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Response{
		body:   io.NopCloser(strings.NewReader("data")),
		cancel: cancel,
		idle:   idle,
	}, ctx
}

// The timer of a read fires just after the read returned data, before it was
// stopped. That late fire must not cancel the stream.
func TestLateIdleTimerDoesNotKillStream(t *testing.T) {
	r, ctx := idleResponse(time.Hour)
	gen := r.arm()
	if r.disarm(gen) {
		t.Fatal("timed out before any fire")
	}
	r.expire(gen) // the late fire
	if ctx.Err() != nil {
		t.Fatal("late timer cancelled a healthy stream")
	}

	// A stale fire during the next read must not cancel it either.
	next := r.arm()
	r.expire(gen)
	if ctx.Err() != nil {
		t.Fatal("stale timer cancelled the next read")
	}
	// The current read's own fire does.
	r.expire(next)
	if ctx.Err() == nil || !r.disarm(next) {
		t.Fatal("current timer did not cancel a silent read")
	}
}

func TestReadDisarmsItsTimer(t *testing.T) {
	r, ctx := idleResponse(20 * time.Millisecond)
	buf := make([]byte, 16)
	if n, err := r.Read(buf); err != nil || string(buf[:n]) != "data" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	time.Sleep(60 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("timer still ran after the read returned")
	}
}
