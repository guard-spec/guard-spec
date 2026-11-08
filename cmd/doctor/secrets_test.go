// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSecrets(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "jwt")
	_ = os.WriteFile(f, []byte("a-long-signing-secret\n"), 0o600)
	run := func(env map[string]string) Result {
		return (&doctor{get: getter(env)}).checkSecrets(context.Background())
	}
	r := run(map[string]string{"JWT_SECRET_FILE": f, "UPSTREAM_LLM_KEY": "sk"})
	if r.Status != OK || !strings.Contains(r.Detail, "file: JWT_SECRET") || !strings.Contains(r.Detail, "env: UPSTREAM_LLM_KEY") || r.Hint == "" {
		t.Errorf("sources: %+v", r)
	}
	if strings.Contains(r.Detail+r.Hint, "a-long-signing-secret") || strings.Contains(r.Detail+r.Hint, "sk,") {
		t.Error("a value in the output")
	}
	if r := run(map[string]string{"JWT_SECRET_FILE": filepath.Join(dir, "missing")}); r.Status != Fail {
		t.Errorf("missing file: %+v", r)
	}
	if r := run(map[string]string{"MFA_ENC_KEY": "vault:secret/x#k"}); r.Status != Fail || !strings.Contains(r.Detail, "VAULT_ADDR") {
		t.Errorf("vault without an address: %+v", r)
	}
	if r := run(map[string]string{"ADMIN_TLS_CERT_FILE": f, "ADMIN_TLS_KEY_FILE": f, "ADMIN_TLS_CLIENT_CA_FILE": f}); r.Status != Fail ||
		!strings.Contains(r.Detail, "admin listener") {
		t.Errorf("bad TLS files: %+v", r)
	}
	if r := run(map[string]string{}); r.Status != OK || r.Hint != "" {
		t.Errorf("nothing set: %+v", r)
	}
}
