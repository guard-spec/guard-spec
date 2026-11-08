// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func resolver(env map[string]string, c *clock) *Resolver {
	r := New(func(k string) string { return env[k] })
	r.now = c.now
	return r
}

func TestEnvAndFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "key")
	if err := os.WriteFile(f, []byte("sk-first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Unix(1000, 0)}
	env := map[string]string{"A": "plain", "B_FILE": f, "C_FILE": filepath.Join(dir, "missing")}
	r := resolver(env, c)
	if got := r.Get("A"); got != "plain" {
		t.Errorf("env: %q", got)
	}
	if got := r.Get("B"); got != "sk-first" {
		t.Errorf("file: %q", got)
	}
	if got := r.Get("C"); got != "" {
		t.Errorf("missing file: %q", got)
	}
	if ok, err := r.Check("C"); ok || err == nil {
		t.Errorf("Check of a missing file: %v %v", ok, err)
	}
	if r.Source("A") != "env" || r.Source("B") != "file" || r.Source("Z") != "" {
		t.Error("Source")
	}
	// The file changes: read again after FileRecheck, not before.
	if err := os.WriteFile(f, []byte("sk-second"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(f, time.Unix(2000, 0), time.Unix(2000, 0))
	if got := r.Get("B"); got != "sk-first" {
		t.Errorf("re-read before FileRecheck: %q", got)
	}
	c.t = c.t.Add(FileRecheck)
	if got := r.Get("B"); got != "sk-second" {
		t.Errorf("after the change: %q", got)
	}
	// Removed while being replaced: the last value stays.
	_ = os.Remove(f)
	c.t = c.t.Add(FileRecheck)
	if got := r.Get("B"); got != "sk-second" {
		t.Errorf("removed: %q", got)
	}
	// The value wins over _FILE.
	env["B"] = "direct"
	if got := r.Get("B"); got != "direct" {
		t.Errorf("value over file: %q", got)
	}
}

func TestVault(t *testing.T) {
	var hits atomic.Int32
	var value atomic.Value
	value.Store("sk-vault-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Vault-Token") != "s.tok" || r.URL.Path != "/v1/secret/data/guard-spec" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{
			"upstream": value.Load().(string), "n": 1}}})
	}))
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("s.tok\n"), 0o600)
	c := &clock{t: time.Unix(1000, 0)}
	env := map[string]string{"VAULT_ADDR": srv.URL, "VAULT_TOKEN_FILE": tokenFile, "SECRETS_VAULT_TTL": "1m",
		"UPSTREAM_KEY_MAIN": "vault:secret/guard-spec#upstream", "NUM": "vault:secret/guard-spec#n",
		"NOKEY": "vault:secret/guard-spec#missing", "BAD": "vault:nopath"}
	r := resolver(env, c)
	if got := r.Get("UPSTREAM_KEY_MAIN"); got != "sk-vault-1" {
		t.Fatalf("vault: %q", got)
	}
	value.Store("sk-vault-2")
	if got := r.Get("UPSTREAM_KEY_MAIN"); got != "sk-vault-1" || hits.Load() != 1 {
		t.Fatalf("within the TTL: %q, %d calls", got, hits.Load())
	}
	c.t = c.t.Add(time.Minute)
	if got := r.Get("UPSTREAM_KEY_MAIN"); got != "sk-vault-2" {
		t.Fatalf("after the TTL: %q", got)
	}
	// Vault down: the last value stays.
	srv.Close()
	c.t = c.t.Add(time.Minute)
	if got := r.Get("UPSTREAM_KEY_MAIN"); got != "sk-vault-2" {
		t.Fatalf("vault down: %q", got)
	}
	for _, name := range []string{"NUM", "NOKEY", "BAD"} {
		if ok, err := r.Check(name); ok || err == nil {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
	if r.Source("UPSTREAM_KEY_MAIN") != "vault" {
		t.Error("Source vault")
	}
}
