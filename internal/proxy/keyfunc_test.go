// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// KeyFunc is called for every request: a key read from a file or Vault
// (internal/secrets) changes without a new proxy.
func TestKeyFuncPerRequest(t *testing.T) {
	var seen atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	key := "sk-one"
	p, err := New(Config{BaseURL: srv.URL, Key: "static", KeyFunc: func() string { return key }})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sk-one", "sk-two"} {
		key = want
		resp, err := p.Forward(context.Background(), "/chat/completions", []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Close()
		if got := seen.Load(); got != "Bearer "+want {
			t.Fatalf("Authorization %q, want Bearer %s", got, want)
		}
	}
}
