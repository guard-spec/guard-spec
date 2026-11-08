// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package datakey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func key(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseLocal(t *testing.T) {
	a, b := key(t), key(t)
	keys, err := ParseLocal("2026-11:" + a + ", " + b)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].ID() != "local:2026-11" || !strings.HasPrefix(keys[1].ID(), "local:k") {
		t.Fatalf("ids %s %s", keys[0].ID(), keys[1].ID())
	}
	again, _ := ParseLocal(b)
	if again[0].ID() != keys[1].ID() {
		t.Error("the fingerprint id is not stable")
	}
	for _, bad := range []string{"", "short", "bad id!:" + a, base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))} {
		if _, err := ParseLocal(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewKeyring(append(keys, keys[0])...); err == nil {
		t.Error("duplicate id accepted")
	}
}

func TestLocalWrap(t *testing.T) {
	keys, _ := ParseLocal(key(t) + "," + key(t))
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")
	w, err := keys[0].Wrap(ctx, dek, []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keys[0].Unwrap(ctx, w, []byte("ad")); err != nil || string(got) != string(dek) {
		t.Fatalf("unwrap: %q %v", got, err)
	}
	if _, err := keys[0].Unwrap(ctx, w, []byte("other")); err == nil {
		t.Error("other aad accepted")
	}
	if _, err := keys[1].Unwrap(ctx, w, []byte("ad")); err == nil {
		t.Error("other key accepted")
	}
}

func TestSealOpen(t *testing.T) {
	org := uuid.New()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	d, err := newDEK(uuid.New(), org, raw)
	if err != nil {
		t.Fatal(err)
	}
	aad := ContentAAD(org, "request_content", "abc")
	s, err := d.Seal(`{"messages":[{"content":"bí mật"}]}`, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(s) || strings.Contains(s, "bí mật") {
		t.Fatalf("not sealed: %s", s)
	}
	if got, err := d.Open(s, aad); err != nil || got != `{"messages":[{"content":"bí mật"}]}` {
		t.Fatalf("open: %q %v", got, err)
	}
	for name, a := range map[string][]byte{
		"other org":    ContentAAD(uuid.New(), "request_content", "abc"),
		"other column": ContentAAD(org, "response_content", "abc"),
		"other row":    ContentAAD(org, "request_content", "abd"),
	} {
		if _, err := d.Open(s, a); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	tampered := s[:len(s)-2] + "AA"
	if _, err := d.Open(tampered, aad); err == nil {
		t.Error("tampered value opened")
	}
	other, _ := newDEK(uuid.New(), org, raw)
	if _, err := other.Open(s, aad); err == nil {
		t.Error("opened with a key of another id")
	}
	for _, bad := range []string{"plain", Prefix + "x", Prefix + "not-a-uuid:AAAA", Prefix + uuid.NewString() + ":***"} {
		if _, _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

// fakeVault serves the Transit encrypt and decrypt endpoints with a local key.
func fakeVault(t *testing.T, token string) *httptest.Server {
	t.Helper()
	inner, _ := ParseLocal(key(t))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v1/transit/encrypt/guard-spec":
			raw, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			ct, _ := inner[0].Wrap(r.Context(), raw, nil)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct)}})
		case "/v1/transit/decrypt/guard-spec":
			ct, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(in["ciphertext"], "vault:v1:"))
			raw, err := inner[0].Unwrap(r.Context(), ct, nil)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["cipher: message authentication failed"]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(raw)}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestVaultTransit(t *testing.T) {
	srv := fakeVault(t, "s.token")
	defer srv.Close()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("s.token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := key(t)
	env := map[string]string{"CONTENT_KEK_VAULT_KEY": "guard-spec", "VAULT_ADDR": srv.URL, "VAULT_TOKEN_FILE": tokenFile, "CONTENT_KEK": "old:" + local}
	ring, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if ring.Active().ID() != "vault:transit/guard-spec" {
		t.Fatalf("active %s", ring.Active().ID())
	}
	if _, ok := ring.Get("local:old"); !ok {
		t.Fatal("local key not kept for unwrapping")
	}
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")
	w, err := ring.Active().Wrap(ctx, dek, nil)
	if err != nil || !strings.HasPrefix(string(w), "vault:v1:") {
		t.Fatalf("wrap: %q %v", w, err)
	}
	if got, err := ring.Active().Unwrap(ctx, w, nil); err != nil || string(got) != string(dek) {
		t.Fatalf("unwrap: %v", err)
	}
	bad := &VaultTransit{Addr: srv.URL, Key: "guard-spec", Token: func() (string, error) { return "wrong", nil }}
	if _, err := bad.Wrap(ctx, dek, nil); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("wrong token: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	if r, err := FromEnv(func(string) string { return "" }); r != nil || err != nil {
		t.Fatalf("nothing set: %v %v", r, err)
	}
	f := filepath.Join(t.TempDir(), "kek")
	_ = os.WriteFile(f, []byte(key(t)+"\n"), 0o600)
	r, err := FromEnv(func(k string) string { return map[string]string{"CONTENT_KEK_FILE": f}[k] })
	if err != nil || r == nil {
		t.Fatalf("file: %v", err)
	}
	if _, err := FromEnv(func(k string) string {
		return map[string]string{"CONTENT_KEK_FILE": f, "CONTENT_KEK": key(t)}[k]
	}); err == nil {
		t.Error("both CONTENT_KEK and CONTENT_KEK_FILE accepted")
	}
	if _, err := FromEnv(func(k string) string { return map[string]string{"CONTENT_KEK_VAULT_KEY": "k"}[k] }); err == nil {
		t.Error("vault key without VAULT_ADDR accepted")
	}
}
