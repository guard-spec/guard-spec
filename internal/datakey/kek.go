// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package datakey encrypts stored content with envelope encryption: each
// organization has its own data key (DEK, AES-256-GCM), kept in the database
// only wrapped by a key-encryption key (KEK) that never leaves the process
// environment or the key service. KEKs come from CONTENT_KEK (local keys) or
// HashiCorp Vault's Transit engine; several can be configured at once so that
// a rotation can still unwrap the DEKs of the previous KEK.
package datakey

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// KEK wraps and unwraps data keys.
type KEK interface {
	// ID names the key; it is stored with every DEK it wrapped.
	ID() string
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// Keyring holds the configured KEKs. The active one wraps new DEKs; the
// others only unwrap, until `control-plane keys rotate` has rewrapped every
// DEK with the active one.
type Keyring struct {
	active KEK
	byID   map[string]KEK
}

// NewKeyring returns a keyring whose first key is the active one.
func NewKeyring(keys ...KEK) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("datakey: no key")
	}
	r := &Keyring{active: keys[0], byID: map[string]KEK{}}
	for _, k := range keys {
		if _, dup := r.byID[k.ID()]; dup {
			return nil, fmt.Errorf("datakey: key id %q configured twice", k.ID())
		}
		r.byID[k.ID()] = k
	}
	return r, nil
}

// Active is the KEK that wraps new DEKs.
func (r *Keyring) Active() KEK { return r.active }

// Get returns the KEK with that id.
func (r *Keyring) Get(id string) (KEK, bool) {
	k, ok := r.byID[id]
	return k, ok
}

// IDs lists the configured KEK ids, the active one first.
func (r *Keyring) IDs() []string {
	ids := []string{r.active.ID()}
	for id := range r.byID {
		if id != r.active.ID() {
			ids = append(ids, id)
		}
	}
	return ids
}

// localKEK is an AES-256-GCM key given in the environment.
type localKEK struct {
	id   string
	aead cipher.AEAD
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ParseLocal reads CONTENT_KEK: a comma-separated list of keys, each 32
// random bytes in base64, optionally prefixed with an id ("2026-11:<base64>").
// A key without an id is named after its SHA-256 fingerprint. The first key
// is the active one.
func ParseLocal(spec string) ([]KEK, error) {
	var keys []KEK
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64 := "", part
		if i := strings.IndexByte(part, ':'); i >= 0 {
			id, b64 = part[:i], part[i+1:]
			if !keyIDPattern.MatchString(id) {
				return nil, fmt.Errorf("CONTENT_KEK: key id %q: use letters, digits, '.', '_' or '-' (at most 64)", id)
			}
		}
		raw, err := decodeKey(b64)
		if err != nil {
			return nil, fmt.Errorf("CONTENT_KEK: %w", err)
		}
		sum := sha256.Sum256(raw)
		if id == "" {
			id = "k" + hex.EncodeToString(sum[:6])
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &localKEK{id: "local:" + id, aead: aead})
	}
	if len(keys) == 0 {
		return nil, errors.New("CONTENT_KEK: no key")
	}
	return keys, nil
}

func decodeKey(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(b64); err == nil {
			if len(raw) != 32 {
				return nil, errors.New("a key must be 32 random bytes in base64 (openssl rand -base64 32)")
			}
			return raw, nil
		}
	}
	return nil, errors.New("a key must be 32 random bytes in base64 (openssl rand -base64 32)")
}

func (k *localKEK) ID() string { return k.id }

func (k *localKEK) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, dek, aad), nil
}

func (k *localKEK) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(wrapped) < n {
		return nil, errors.New("datakey: wrapped key too short")
	}
	return k.aead.Open(nil, wrapped[:n], wrapped[n:], aad)
}

// VaultTransit is a KEK held by HashiCorp Vault's Transit secrets engine:
// the key never leaves Vault, which encrypts and decrypts the DEKs. Vault
// keeps the key versions; `vault write -f transit/keys/<name>/rotate` adds
// one and `control-plane keys rotate` rewraps the DEKs with it.
type VaultTransit struct {
	Addr      string // VAULT_ADDR, e.g. https://vault.example:8200
	Mount     string // transit mount, default "transit"
	Key       string // transit key name
	Namespace string // VAULT_NAMESPACE (Vault Enterprise / HCP), optional
	// Token returns the Vault token (VAULT_TOKEN, or re-read from
	// VAULT_TOKEN_FILE so that an agent can renew it).
	Token  func() (string, error)
	Client *http.Client
}

// ID is "vault:<mount>/<key>".
func (v *VaultTransit) ID() string { return "vault:" + v.mount() + "/" + v.Key }

func (v *VaultTransit) mount() string {
	if v.Mount == "" {
		return "transit"
	}
	return strings.Trim(v.Mount, "/")
}

// Wrap sends the DEK to Vault's encrypt endpoint. aad is not sent (Transit
// supports it only for some key types); the DEK row binds the key to its
// organization instead.
func (v *VaultTransit) Wrap(ctx context.Context, dek, _ []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.call(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}, &out); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:") {
		return nil, errors.New("vault transit: no ciphertext in the answer")
	}
	return []byte(out.Data.Ciphertext), nil
}

// Unwrap sends the wrapped DEK to Vault's decrypt endpoint.
func (v *VaultTransit) Unwrap(ctx context.Context, wrapped, _ []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.call(ctx, "decrypt", map[string]string{"ciphertext": string(wrapped)}, &out); err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(dek) != 32 {
		return nil, errors.New("vault transit: the answer is not a 32-byte key")
	}
	return dek, nil
}

func (v *VaultTransit) call(ctx context.Context, op string, body any, out any) error {
	token, err := v.Token()
	if err != nil {
		return fmt.Errorf("vault token: %w", err)
	}
	b, _ := json.Marshal(body)
	u := strings.TrimRight(v.Addr, "/") + "/v1/" + v.mount() + "/" + op + "/" + v.Key
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vault transit %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("vault transit %s: HTTP %d %s", op, resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return json.Unmarshal(data, out)
}

// tokenSource reads VAULT_TOKEN, or VAULT_TOKEN_FILE again after a minute.
func tokenSource(get func(string) string) func() (string, error) {
	if t := strings.TrimSpace(get("VAULT_TOKEN")); t != "" {
		return func() (string, error) { return t, nil }
	}
	path := strings.TrimSpace(get("VAULT_TOKEN_FILE"))
	var mu sync.Mutex
	var cached string
	var at time.Time
	return func() (string, error) {
		if path == "" {
			return "", errors.New("set VAULT_TOKEN or VAULT_TOKEN_FILE")
		}
		mu.Lock()
		defer mu.Unlock()
		if cached != "" && time.Since(at) < time.Minute {
			return cached, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		cached, at = strings.TrimSpace(string(b)), time.Now()
		if cached == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return cached, nil
	}
}

// FromEnv builds the keyring of the environment, or returns nil when no KEK
// is configured:
//
//	CONTENT_KEK            local keys, "id:base64,..." (first = active)
//	CONTENT_KEK_FILE       the same, read from a file (a mounted secret)
//	CONTENT_KEK_VAULT_KEY  a Vault Transit key name; with VAULT_ADDR and
//	                       VAULT_TOKEN or VAULT_TOKEN_FILE (and optionally
//	                       CONTENT_KEK_VAULT_MOUNT, VAULT_NAMESPACE)
//
// With both Vault and local keys, Vault is active and the local keys only
// unwrap, which is how an installation moves from local keys to Vault.
func FromEnv(get func(string) string) (*Keyring, error) {
	var keys []KEK
	if name := strings.TrimSpace(get("CONTENT_KEK_VAULT_KEY")); name != "" {
		addr := strings.TrimSpace(get("VAULT_ADDR"))
		if addr == "" {
			return nil, errors.New("CONTENT_KEK_VAULT_KEY needs VAULT_ADDR")
		}
		keys = append(keys, &VaultTransit{
			Addr: addr, Mount: get("CONTENT_KEK_VAULT_MOUNT"), Key: name,
			Namespace: strings.TrimSpace(get("VAULT_NAMESPACE")), Token: tokenSource(get),
		})
	}
	spec := get("CONTENT_KEK")
	if f := strings.TrimSpace(get("CONTENT_KEK_FILE")); f != "" {
		if strings.TrimSpace(spec) != "" {
			return nil, errors.New("set CONTENT_KEK or CONTENT_KEK_FILE, not both")
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("CONTENT_KEK_FILE: %w", err)
		}
		spec = string(b)
	}
	if strings.TrimSpace(spec) != "" {
		local, err := ParseLocal(spec)
		if err != nil {
			return nil, err
		}
		keys = append(keys, local...)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return NewKeyring(keys...)
}
