// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHost(t *testing.T) {
	for in, want := range map[string]string{
		"":               "127.0.0.1:8080",
		":8080":          "127.0.0.1:8080",
		"0.0.0.0:9000":   "127.0.0.1:9000",
		"[::]:8080":      "[::1]:8080",
		"10.0.0.5:8080":  "10.0.0.5:8080",
		"localhost:8181": "localhost:8181",
		"bogus":          "127.0.0.1:8080",
	} {
		if got := healthHost(in); got != want {
			t.Errorf("healthHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	env := func(k string) string {
		if k == "LISTEN_ADDR" {
			return ":" + port
		}
		return ""
	}
	if code := runHealth([]string{"/health"}, env, io.Discard); code != 0 {
		t.Fatalf("/health: exit %d", code)
	}
	if code := runHealth(nil, env, io.Discard); code != 1 {
		t.Fatalf("/readyz 503: exit %d, want 1", code)
	}
	if code := runHealth([]string{"health"}, env, io.Discard); code != 2 {
		t.Fatalf("bad path: exit %d, want 2", code)
	}
	srv.Close()
	if code := runHealth(nil, env, io.Discard); code != 1 {
		t.Fatalf("closed: exit %d, want 1", code)
	}
}
