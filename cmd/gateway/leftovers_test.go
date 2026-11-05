package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
)

func TestUpstreamFailuresAuditedAsError(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{"5xx", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, 0},
		{"4xx", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, 0},
		{"timeout", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, 100 * time.Millisecond},
		{"stream failure", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := newFakeUpstream(t, tt.handler)
			h := startGateway(t, up.URL, func(gw *gateway) {
				if tt.timeout > 0 {
					gw.upstream, _ = proxy.New(proxy.Config{BaseURL: up.URL + "/v1", Timeout: tt.timeout})
				}
			})
			h.post(t, "/v1/chat/completions", clean, nil)
			if row := h.oneRow(t); row.Action != "error" {
				t.Errorf("row = %+v", row)
			}
		})
	}
}

// A log rule records its match and lets the next rule decide.
func TestLogRuleThenBlock(t *testing.T) {
	logged := rule(policy.ActionLog, "request.model", "=", "m")
	block := rule(policy.ActionBlock, "request.tokens", ">=", 0)
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, withRules(logged, block))
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	assertBlocked(t, resp, body)
	if n := up.hits.Load(); n != 0 {
		t.Errorf("upstream hits = %d", n)
	}
	if row := h.oneRow(t); row.Action != "block" || row.RuleID != block.ID {
		t.Errorf("row = %+v", row)
	}
}

// rawRequest sends a request on its own connection and returns the connection.
func rawRequest(t *testing.T, url, body string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
		"x-api-key: test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	return conn
}

// A client that hangs up while the upstream has not sent a byte cancels the
// upstream at once, not after the upstream timeout.
func TestClientLeavingBeforeFirstByteCancelsUpstream(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			arrived := make(chan struct{})
			cancelled := make(chan time.Time, 1)
			up := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if stream {
					// Headers out, then silence: the first data byte never comes.
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				close(arrived)
				<-r.Context().Done()
				cancelled <- time.Now()
			})
			h := startGateway(t, up.URL, nil) // upstream timeout 30s
			conn := rawRequest(t, h.url, clean)
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("request never reached the upstream")
			}
			if stream {
				// fasthttp sends the headers with the first body bytes, so the
				// client sees nothing yet; give the stream writer time to start.
				time.Sleep(200 * time.Millisecond)
			}
			left := time.Now()
			conn.Close()
			select {
			case at := <-cancelled:
				if d := at.Sub(left); d < 0 || d > 3*time.Second {
					t.Errorf("upstream cancelled %s after the client left", d)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("upstream still waiting after the client left")
			}
			h.oneRow(t)
		})
	}
}

// Watching the connection must not disturb keep-alive: the next request on the
// same connection is served normally.
func TestKeepAliveAfterWatchedRequest(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, nil)
	conn := rawRequest(t, h.url, clean)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("response %d: status %d", i, resp.StatusCode)
		}
		if i == 0 {
			fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
				"x-api-key: test\r\nContent-Length: %d\r\n\r\n%s", len(clean), clean)
		}
	}
	if n := up.hits.Load(); n != 2 {
		t.Errorf("upstream hits = %d", n)
	}
}

func TestAuditRecordAfterCloseIsWrittenSynchronously(t *testing.T) {
	var written atomic.Int32
	a := newAuditLog(func(requestEntry) {
		time.Sleep(10 * time.Millisecond)
		written.Add(1)
	})
	release := a.hold()
	a.record(requestEntry{})
	closed := make(chan struct{})
	go func() {
		a.close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("close returned while a request was still held")
	case <-time.After(50 * time.Millisecond):
	}
	a.record(requestEntry{}) // the held request's row, after close began
	if written.Load() != 2 {
		t.Errorf("late row not written before record returned: %d", written.Load())
	}
	release()
	<-closed
	a.hold()() // after close: counts nothing
	a.record(requestEntry{})
	if written.Load() != 3 {
		t.Errorf("written = %d", written.Load())
	}
}

// Run with -race: records, holds and close from many goroutines.
func TestAuditConcurrentCloseNeverRaces(t *testing.T) {
	var written atomic.Int32
	a := newAuditLog(func(requestEntry) { written.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := a.hold()
			a.record(requestEntry{})
			release()
		}()
	}
	a.close()
	wg.Wait()
	if written.Load() != 50 {
		t.Errorf("written = %d, want 50", written.Load())
	}
}
