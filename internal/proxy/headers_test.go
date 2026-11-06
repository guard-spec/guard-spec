package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateHeaders(t *testing.T) {
	ok := []map[string]string{
		nil,
		{"OpenAI-Organization": "org_x"},
		{"OpenAI-Project": "proj_abc123def456ghi789jkl0"},
		{"anthropic-version": "2023-06-01", "X-Team": "search platform"},
	}
	for _, h := range ok {
		if err := ValidateHeaders(h); err != nil {
			t.Errorf("%v refused: %v", h, err)
		}
	}
	bad := []map[string]string{
		{"Authorization": "x"},
		{"x-api-key": "x"},
		{"X-Auth-User": "x"},
		{"Host": "evil"},
		{"X-Forwarded-For": "1.2.3.4"},
		{"bad name": "x"},
		{"X-Org": "sk-proj-abcdef"},
		{"X-Org": "Bearer abc"},
		{"X-Org": "AIzaSyD-1234"},
		{"X-Org": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"},
		{"X-Org": "line\nbreak"},
		{"X-Org": strings.Repeat("a ", 300)},
	}
	for _, h := range bad {
		if err := ValidateHeaders(h); err == nil {
			t.Errorf("%v accepted", h)
		}
	}
	many := map[string]string{}
	for i := range 21 {
		many["X-H"+string(rune('a'+i))] = "v"
	}
	if ValidateHeaders(many) == nil {
		t.Error("21 headers accepted")
	}
}

func TestProxyHeadersKeyAndVersion(t *testing.T) {
	var got http.Header
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, query = r.Header.Clone(), r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}],"secret":"do-not-echo"}`))
	}))
	defer srv.Close()
	p, err := New(Config{BaseURL: srv.URL, Key: "k-123", KeyHeader: "api-key", APIVersion: "2024-10-21",
		Headers: map[string]string{"OpenAI-Organization": "org_x", "Authorization": "dropped"}})
	if err != nil {
		t.Fatal(err)
	}
	res := p.Probe(context.Background())
	if !res.OK || res.Status != 200 || len(res.Models) != 2 || res.Models[0] != "gpt-4o" {
		t.Fatalf("probe: %+v", res)
	}
	if got.Get("api-key") != "k-123" || got.Get("Authorization") != "" || got.Get("OpenAI-Organization") != "org_x" {
		t.Errorf("headers: %v", got)
	}
	if query != "api-version=2024-10-21" {
		t.Errorf("query %q", query)
	}
}

func TestProbeErrorsAndPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"message":"key sk-leaked is wrong"}}`))
	}))
	defer srv.Close()
	p, _ := New(Config{BaseURL: srv.URL})
	res := p.Probe(context.Background())
	if res.OK || res.Status != 401 || strings.Contains(res.Error, "leaked") {
		t.Errorf("401: %+v", res)
	}
	p, _ = New(Config{BaseURL: srv.URL, DenyPrivate: true})
	res = p.Probe(context.Background())
	if res.OK || !strings.Contains(res.Error, "not allowed") {
		t.Errorf("private: %+v", res)
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	p, _ := New(Config{BaseURL: srv.URL, Retries: 1})
	resp, err := p.Forward(context.Background(), "/chat/completions", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if calls.Load() != 2 {
		t.Errorf("calls = %d", calls.Load())
	}
	// A 4xx is about the request and is not retried.
	calls.Store(0)
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(400)
	}))
	defer srv4.Close()
	p, _ = New(Config{BaseURL: srv4.URL, Retries: 3})
	if _, err := p.Forward(context.Background(), "/chat/completions", []byte(`{}`)); err == nil || calls.Load() != 1 {
		t.Errorf("4xx: %v calls %d", err, calls.Load())
	}
}

func TestCallHeaders(t *testing.T) {
	var got http.Header
	var method string
	var bodyLen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, method, bodyLen = r.Header.Clone(), r.Method, r.ContentLength
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	p, err := New(Config{BaseURL: srv.URL, Key: "sk-ant-gw", Headers: map[string]string{"anthropic-version": "2024-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	call := Call{KeyHeader: "x-api-key", Header: http.Header{
		"Anthropic-Version": {"2023-06-01"}, // the configured header wins
		"Anthropic-Beta":    {"prompt-caching-2024-07-31"},
		"X-Api-Key":         {"client-key"}, // credential names are dropped
		"Authorization":     {"Bearer client"},
		"X-Forwarded-For":   {"1.2.3.4"},
		"Host":              {"evil"},
		"X-Bad":             {"a\r\nInjected: 1"},
	}}
	resp, err := p.Do(context.Background(), "/messages", []byte(`{}`), call)
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	want := map[string]string{"X-Api-Key": "sk-ant-gw", "Anthropic-Version": "2024-01-01",
		"Anthropic-Beta": "prompt-caching-2024-07-31", "Authorization": "", "X-Forwarded-For": "", "X-Bad": "",
		"Content-Type": "application/json"}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	if method != http.MethodPost {
		t.Errorf("method %s", method)
	}
	resp, err = p.Do(context.Background(), "/models", nil, Call{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if method != http.MethodGet || bodyLen != 0 || got.Get("Content-Type") != "" || got.Get("Authorization") != "Bearer sk-ant-gw" {
		t.Errorf("GET: %s %d %v", method, bodyLen, got)
	}
}
