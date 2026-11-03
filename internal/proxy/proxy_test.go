package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func forward(t *testing.T, handler http.HandlerFunc, cfg Config) (*Response, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL + "/v1/"
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p.Forward(context.Background(), "/chat/completions", []byte(`{}`))
}

func TestNewRejectsBadURL(t *testing.T) {
	for _, u := range []string{"localhost:11434", "ftp://host", "http://", "://"} {
		if _, err := New(Config{BaseURL: u}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

func TestStatusMapping(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantStatus int
		wantMsg    string
		notWant    string
	}{
		{"bad request keeps its message", 400, `{"error":{"message":"bad temperature"}}`, 400, "bad temperature", ""},
		{"not found, flat error", 404, `{"error":"model not found"}`, 404, "model not found", ""},
		{"4xx not json", 422, `<html>`, 422, "Unprocessable Entity", "html"},
		{"bad upstream key is ours, not the client's", 401, `{"error":{"message":"bad key sk-abc"}}`, 502, "credentials", "sk-abc"},
		{"forbidden", 403, `{}`, 502, "credentials", ""},
		{"5xx hides the body", 500, `{"error":{"message":"at /srv/app.py line 3"}}`, 502, "upstream error", "/srv"},
		{"unavailable", 503, ``, 502, "upstream error", ""},
		{"upstream gateway timeout is still an upstream error", 504, ``, 502, "upstream error", ""},
		{"redirect not followed", 302, ``, 502, "unexpected", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := forward(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "http://elsewhere.invalid/")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}, Config{})
			var pe *Error
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v", err)
			}
			if pe.Status != tt.wantStatus || !strings.Contains(pe.Message, tt.wantMsg) {
				t.Errorf("got %d %q", pe.Status, pe.Message)
			}
			if tt.notWant != "" && strings.Contains(pe.Message, tt.notWant) {
				t.Errorf("leaked: %q", pe.Message)
			}
		})
	}
}

func TestLongUpstreamMessageIsTruncated(t *testing.T) {
	_, err := forward(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":{"message":"%s"}}`, strings.Repeat("x", 5000))
	}, Config{})
	var pe *Error
	if !errors.As(err, &pe) || len(pe.Message) != maxMessageLen {
		t.Errorf("err = %v", err)
	}
}

func TestTimeToFirstByte(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	start := time.Now()
	_, err := forward(t, func(http.ResponseWriter, *http.Request) { <-done }, Config{Timeout: 100 * time.Millisecond})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 504 {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("took too long")
	}
}

func TestSlowFirstByteWithinTimeoutSucceeds(t *testing.T) {
	r, err := forward(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}, Config{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if data, err := r.ReadAll(); err != nil || string(data) != "ok" {
		t.Errorf("got %q %v", data, err)
	}
}

// A stream outliving the timeout is fine as long as data keeps arriving.
func TestLongStreamIsNotKilled(t *testing.T) {
	const timeout = 150 * time.Millisecond
	r, err := forward(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 8; i++ {
			fmt.Fprint(w, "x")
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}, Config{Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.Stream() {
		t.Error("not detected as a stream")
	}
	start := time.Now()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 8 || time.Since(start) < timeout {
		t.Errorf("read %d bytes in %s", len(data), time.Since(start))
	}
}

func TestSilentStreamTimesOut(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	r, err := forward(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "x")
		w.(http.Flusher).Flush()
		<-done
	}, Config{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = io.ReadAll(r)
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 504 {
		t.Errorf("err = %v", err)
	}
}

func TestConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	p, err := New(Config{BaseURL: "http://" + addr})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Forward(context.Background(), "/x", nil)
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 502 || strings.Contains(pe.Message, addr) {
		t.Errorf("err = %v", err)
	}
}
