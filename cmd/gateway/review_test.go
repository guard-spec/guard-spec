package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A client that half-closes (shutdown(SHUT_WR)) and waits for the answer gets
// it with CLIENT_HALF_CLOSE=wait. By default a FIN counts as leaving.
func TestHalfCloseClient(t *testing.T) {
	for _, wait := range []bool{true, false} {
		t.Run(fmt.Sprintf("wait=%v", wait), func(t *testing.T) {
			cancelled := make(chan struct{}, 1)
			up := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(300 * time.Millisecond):
					okUpstream(w, r)
				case <-r.Context().Done():
					cancelled <- struct{}{}
				}
			})
			h := startGateway(t, up.URL, func(gw *gateway) { gw.waitOnHalfClose = wait })
			conn := rawRequest(t, h.url, clean)
			defer conn.Close()
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if wait {
				if err != nil {
					t.Fatalf("no response after half-close: %v", err)
				}
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 || !strings.Contains(string(body), "chatcmpl-real") {
					t.Errorf("got %d %s", resp.StatusCode, body)
				}
				if len(cancelled) != 0 {
					t.Error("upstream cancelled for a half-closed client")
				}
				return
			}
			// Default: the FIN cancels the upstream (often before it even got the
			// request), and the half-closed client reads a 502.
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 502 {
				t.Errorf("default mode: status %d, want 502", resp.StatusCode)
			}
			if row := h.oneRow(t); row.Action != "error" {
				t.Errorf("row = %+v", row)
			}
		})
	}
}

func TestToolCallArgumentsGuarded(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"c","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
			"tool_calls":[{"id":"t1","type":"function","function":{"name":"send","arguments":"{\"to\":\"lan@corp.vn\",\"n\":3}"}}]}}]}`)
	})
	h := startGateway(t, up.URL, nil)
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	var out struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct{ Name, Arguments string }
				} `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	args := out.Choices[0].Message.ToolCalls[0].Function.Arguments
	if args != `{"n":3,"to":"[REDACTED:email]"}` || !json.Valid([]byte(args)) {
		t.Errorf("arguments = %q", args)
	}
}

func TestCanaryInToolCallBlocked(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			var up *fakeUpstream
			up = newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				up.mu.Lock()
				canary := canaryRe.FindString(up.body)
				up.mu.Unlock()
				args, _ := json.Marshal(`{"q":"` + canary + `"}`)
				if !stream {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"id":"c","choices":[{"index":0,"message":{"tool_calls":[{"index":0,"function":{"name":"f","arguments":%s}}]}}]}`, args)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				half := len(args) / 2
				for _, frag := range []string{string(args[:half]) + `"`, `"` + string(args[half:])} {
					fmt.Fprintf(w, "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":%s}}]},\"finish_reason\":null}]}\n\n", frag)
				}
				fmt.Fprint(w, "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
			})
			// Redact mode: tool-call arguments are still blocked.
			h := startGateway(t, up.URL, withCanary("redact"))
			body := clean
			if stream {
				body = `{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`
			}
			resp, got := h.post(t, "/v1/chat/completions", body, nil)
			if canaryRe.MatchString(got) || !strings.Contains(got, "content_filter") {
				t.Errorf("got %d %s", resp.StatusCode, got)
			}
			if row := h.oneRow(t); row.Action != "output_leak" {
				t.Errorf("row = %+v", row)
			}
		})
	}
}

func TestStreamContentPartsThatAreNotText(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, `data: {"id":"c","choices":[{"index":0,"delta":{"content":[{"type":"image_url","image_url":{"url":"https://evil.com/x.png?d=1"}}]}}]}`+"\n\n")
	})
	h := startGateway(t, up.URL, nil)
	_, body := h.post(t, "/v1/chat/completions",
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`, nil)
	if strings.Contains(body, "evil.com") || !strings.Contains(body, "could not be checked") {
		t.Errorf("body = %q", body)
	}
	if row := h.oneRow(t); row.Action != "error" {
		t.Errorf("row = %+v", row)
	}
}
