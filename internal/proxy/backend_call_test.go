// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A custom backend call: its own path, query and content type, no body when
// empty, and 4xx answers handed back except the credential ones.
func TestBackendCall(t *testing.T) {
	var gotURI, gotType, gotBody string
	var hadBody bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		gotURI, gotType, gotBody, hadBody = r.RequestURI, r.Header.Get("Content-Type"), string(data), r.ContentLength > 0
		switch r.URL.Path {
		case "/api/missing":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"detail":"no such order"}`))
		case "/api/auth":
			w.WriteHeader(401)
		case "/api/proxy-auth":
			w.WriteHeader(407)
		}
	}))
	defer srv.Close()
	p, err := New(Config{BaseURL: srv.URL + "/api"})
	if err != nil {
		t.Fatal(err)
	}
	call := Call{Method: http.MethodPut, URLPath: "/orders/7", RawQuery: "a=1&b=%20", ContentType: "text/plain",
		PassClientErrors: true}
	resp, err := p.Do(context.Background(), "/backend", []byte("hello"), call)
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if gotURI != "/api/orders/7?a=1&b=%20" || gotType != "text/plain" || gotBody != "hello" {
		t.Errorf("sent %s %q %q", gotURI, gotType, gotBody)
	}
	call = Call{Method: http.MethodDelete, URLPath: "/orders/7", PassClientErrors: true}
	if resp, err = p.Do(context.Background(), "/backend", nil, call); err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if hadBody || gotType != "" {
		t.Errorf("empty body sent: type %q", gotType)
	}
	call.URLPath = "/missing"
	resp, err = p.Do(context.Background(), "/backend", nil, call)
	if err != nil || resp.Status != 404 {
		t.Fatalf("404: %v %v", resp, err)
	}
	if data, _ := resp.ReadAll(); string(data) != `{"detail":"no such order"}` {
		t.Errorf("404 body %s", data)
	}
	resp.Close()
	for _, path := range []string{"/auth", "/proxy-auth"} {
		call.URLPath = path
		_, err = p.Do(context.Background(), "/backend", nil, call)
		var e *Error
		if !errors.As(err, &e) || e.Code != "upstream_auth_failed" {
			t.Errorf("%s: %v", path, err)
		}
	}
}

// The proxy refuses a backend path or query that could change the URL.
func TestBackendCallRefusesBadURL(t *testing.T) {
	p, err := New(Config{BaseURL: "http://127.0.0.1:1/api"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Call{
		{URLPath: "x"}, {URLPath: "/a b"}, {URLPath: "/a#b"}, {URLPath: "/a?b"}, {URLPath: `/a\b`},
		{URLPath: "/a\nb"}, {URLPath: "/ok", RawQuery: "a=1#frag"}, {URLPath: "/ok", RawQuery: "a b"},
	} {
		var e *Error
		if _, err := p.Do(context.Background(), "/backend", nil, c); !errors.As(err, &e) || e.Code != "invalid_path" {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, c := range []Call{{URLPath: "/a/b%20c~d;e=f@g"}, {URLPath: "/ok", RawQuery: `f[a]=1&b="x"|y?z`}} {
		if !backendPathRe.MatchString(c.URLPath) || !backendQueryRe.MatchString(c.RawQuery) {
			t.Errorf("refused %+v", c)
		}
	}
}
