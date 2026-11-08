// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package secrets reads secret settings from more places than the process
// environment, and picks up changes without a restart (RF-da721d14):
//
//	NAME=value                       the value itself (as before)
//	NAME=vault:<mount>/<path>#<key>  a key of a HashiCorp Vault KV v2 secret,
//	                                 with VAULT_ADDR and VAULT_TOKEN or
//	                                 VAULT_TOKEN_FILE (and VAULT_NAMESPACE)
//	NAME_FILE=/run/secrets/name      the file's content, without the final
//	                                 newline (Docker and Kubernetes secrets)
//
// Files are read again when they change (checked at most every
// FileRecheck); Vault values are kept for SECRETS_VAULT_TTL (default 5
// minutes). When Vault cannot be reached the last value it gave is kept and
// the error logged; with no value yet, the setting reads empty.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// FileRecheck is how often a file's modification time is looked at.
const FileRecheck = 10 * time.Second

// Resolver resolves secret settings. The zero value is not usable; use New
// or Default.
type Resolver struct {
	env    func(string) string
	client *http.Client
	now    func() time.Time
	ttl    time.Duration

	mu    sync.Mutex
	files map[string]*fileEntry
	vault map[string]*vaultEntry
}

type fileEntry struct {
	value   string
	mod     time.Time
	checked time.Time
	err     error
}

type vaultEntry struct {
	value   string
	fetched time.Time
	ok      bool
}

// New returns a resolver over env (os.Getenv in production).
func New(env func(string) string) *Resolver {
	ttl := 5 * time.Minute
	if v := strings.TrimSpace(env("SECRETS_VAULT_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			ttl = d
		}
	}
	return &Resolver{env: env, client: &http.Client{Timeout: 10 * time.Second}, now: time.Now, ttl: ttl,
		files: map[string]*fileEntry{}, vault: map[string]*vaultEntry{}}
}

var (
	defaultOnce sync.Once
	defaultRes  *Resolver
)

// Default is the process-wide resolver over os.Getenv.
func Default() *Resolver {
	defaultOnce.Do(func() { defaultRes = New(os.Getenv) })
	return defaultRes
}

// Getenv resolves name with the default resolver; a drop-in for os.Getenv
// on secret settings.
func Getenv(name string) string { return Default().Get(name) }

// Get resolves name: its value, a Vault reference in it, or NAME_FILE.
func (r *Resolver) Get(name string) string {
	v := r.env(name)
	if ref, ok := strings.CutPrefix(v, "vault:"); ok {
		return r.fromVault(name, ref)
	}
	if v != "" {
		return v
	}
	if path := strings.TrimSpace(r.env(name + "_FILE")); path != "" {
		val, err := r.fromFile(path)
		if err != nil {
			slog.Error("secret file unreadable", "setting", name+"_FILE", "err", err)
		}
		return val
	}
	return ""
}

// Source names where name comes from, for doctor: "env", "file", "vault" or
// "" when not set. It never returns the value.
func (r *Resolver) Source(name string) string {
	v := r.env(name)
	switch {
	case strings.HasPrefix(v, "vault:"):
		return "vault"
	case v != "":
		return "env"
	case strings.TrimSpace(r.env(name+"_FILE")) != "":
		return "file"
	}
	return ""
}

// Check resolves name and reports an error instead of logging it, for
// doctor and startup checks.
func (r *Resolver) Check(name string) (bool, error) {
	v := r.env(name)
	if ref, ok := strings.CutPrefix(v, "vault:"); ok {
		val, err := r.readVault(context.Background(), ref)
		return val != "", err
	}
	if v != "" {
		return true, nil
	}
	if path := strings.TrimSpace(r.env(name + "_FILE")); path != "" {
		val, err := r.fromFile(path)
		return val != "", err
	}
	return false, nil
}

func (r *Resolver) fromFile(path string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fileLocked(path, r.files)
}

// fileLocked reads path, again when its modification time changed.
func (r *Resolver) fileLocked(path string, cache map[string]*fileEntry) (string, error) {
	now := r.now()
	e := cache[path]
	if e != nil && now.Sub(e.checked) < FileRecheck {
		return e.value, e.err
	}
	if e == nil {
		e = &fileEntry{}
		cache[path] = e
	}
	e.checked = now
	fi, err := os.Stat(path)
	if err != nil {
		e.err = err
		return e.value, err // keep the last value: a secret being replaced
	}
	if !fi.ModTime().Equal(e.mod) || e.value == "" {
		b, err := os.ReadFile(path)
		if err != nil {
			e.err = err
			return e.value, err
		}
		e.value, e.mod, e.err = strings.TrimRight(string(b), "\r\n"), fi.ModTime(), nil
	}
	return e.value, nil
}

func (r *Resolver) fromVault(name, ref string) string {
	r.mu.Lock()
	e := r.vault[ref]
	if e != nil && e.ok && r.now().Sub(e.fetched) < r.ttl {
		v := e.value
		r.mu.Unlock()
		return v
	}
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	val, err := r.readVault(ctx, ref)
	r.mu.Lock()
	defer r.mu.Unlock()
	if e == nil {
		e = &vaultEntry{}
		r.vault[ref] = e
	}
	if err != nil {
		slog.Error("secret from Vault unavailable; keeping the last value", "setting", name, "err", err)
		return e.value
	}
	e.value, e.fetched, e.ok = val, r.now(), true
	return val
}

// readVault reads <mount>/<path>#<key> from Vault's KV v2 engine.
func (r *Resolver) readVault(ctx context.Context, ref string) (string, error) {
	pathPart, key, ok := strings.Cut(ref, "#")
	mount, path, ok2 := strings.Cut(strings.Trim(pathPart, "/"), "/")
	if !ok || !ok2 || key == "" || path == "" {
		return "", fmt.Errorf("vault reference %q: use vault:<mount>/<path>#<key>", ref)
	}
	addr := strings.TrimRight(strings.TrimSpace(r.env("VAULT_ADDR")), "/")
	if addr == "" {
		return "", errors.New("a vault: reference needs VAULT_ADDR")
	}
	token, err := r.vaultToken()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/v1/"+mount+"/data/"+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	if ns := strings.TrimSpace(r.env("VAULT_NAMESPACE")); ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault %s/%s: HTTP %d", mount, path, resp.StatusCode)
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("vault %s/%s: %w", mount, path, err)
	}
	v, present := out.Data.Data[key]
	if !present {
		return "", fmt.Errorf("vault %s/%s has no key %q", mount, path, key)
	}
	s, isString := v.(string)
	if !isString {
		return "", fmt.Errorf("vault %s/%s#%s is not a string", mount, path, key)
	}
	return s, nil
}

// vaultToken returns VAULT_TOKEN, or VAULT_TOKEN_FILE's content (read again
// when the file changes, so that a Vault agent can renew it).
func (r *Resolver) vaultToken() (string, error) {
	if t := strings.TrimSpace(r.env("VAULT_TOKEN")); t != "" {
		return t, nil
	}
	path := strings.TrimSpace(r.env("VAULT_TOKEN_FILE"))
	if path == "" {
		return "", errors.New("a vault: reference needs VAULT_TOKEN or VAULT_TOKEN_FILE")
	}
	v, err := r.fromFile(path)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

// Export resolves names that come from a file or Vault and puts the values
// in the process environment, for libraries that read the environment
// themselves (pgx reads PGPASSWORD). Values set directly are left alone.
// Done once at startup: such a value changes with a restart.
func Export(names ...string) error {
	r := Default()
	for _, name := range names {
		switch r.Source(name) {
		case "file", "vault":
			ok, err := r.Check(name)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if ok {
				if err := os.Setenv(name, r.Get(name)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
