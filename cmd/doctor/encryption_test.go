// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestCheckEncryption(t *testing.T) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	k := base64.StdEncoding.EncodeToString(b)
	run := func(env map[string]string) Result {
		d := &doctor{get: getter(env), opts: Options{Timeout: 2 * time.Second}}
		return d.checkEncryption(context.Background())
	}
	if r := run(map[string]string{}); r.Status != OK {
		t.Errorf("nothing stored: %+v", r)
	}
	if r := run(map[string]string{"AUDIT_STORE_CONTENT": "true"}); r.Status != Warn || !strings.Contains(r.Detail, "in the clear") {
		t.Errorf("stored in the clear: %+v", r)
	}
	if r := run(map[string]string{"CONTENT_KEK": "k1:" + k}); r.Status != OK || !strings.Contains(r.Detail, "local:k1 works") {
		t.Errorf("with a KEK: %+v", r)
	}
	if r := run(map[string]string{"CONTENT_KEK": "not a key"}); r.Status != Fail {
		t.Errorf("bad KEK: %+v", r)
	}
	if r := run(map[string]string{"CONTENT_KEK_VAULT_KEY": "gs", "VAULT_ADDR": "http://127.0.0.1:1", "VAULT_TOKEN": "x"}); r.Status != Fail ||
		!strings.Contains(r.Detail, "does not work") {
		t.Errorf("unreachable Vault: %+v", r)
	}
}
