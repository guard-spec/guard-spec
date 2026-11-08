// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/guard-spec/guard-spec/internal/secrets"
	"github.com/guard-spec/guard-spec/internal/tlsreload"
)

// secretNames are the settings that hold secrets, in either service.
var secretNames = []string{"PGPASSWORD", "UPSTREAM_LLM_KEY", "GATEWAY_ADMIN_TOKEN", "SCAN_CACHE_REDIS_URL",
	"JWT_SECRET", "MFA_ENC_KEY", "ADMIN_PASSWORD", "AUDIT_SIGNING_KEY", "SMTP_URL", "TELEGRAM_BOT_TOKEN",
	"TELEGRAM_WEBHOOK_SECRET"}

// checkSecrets reports where the secret settings come from (the
// environment, a file, Vault), fails when a file or a Vault reference cannot
// be read, and checks the mutual TLS files of the admin listener and of the
// control plane's calls to it. It never prints a value.
func (d *doctor) checkSecrets(_ context.Context) Result {
	r := secrets.New(d.get)
	names := append([]string{}, secretNames...)
	// Named upstream keys and channel secrets: whatever UPSTREAM_KEY_* the
	// environment has is not known here; the ones given as files are.
	by := map[string][]string{}
	var problems []string
	for _, n := range names {
		src := r.Source(n)
		if src == "" {
			continue
		}
		by[src] = append(by[src], n)
		if src != "env" {
			if ok, err := r.Check(n); err != nil {
				problems = append(problems, fmt.Sprintf("%s (%s): %v", n, src, err))
			} else if !ok {
				problems = append(problems, fmt.Sprintf("%s (%s) is empty", n, src))
			}
		}
	}
	for _, tls := range []struct{ what, cert, key, ca string }{
		{"admin listener", "ADMIN_TLS_CERT_FILE", "ADMIN_TLS_KEY_FILE", "ADMIN_TLS_CLIENT_CA_FILE"},
		{"calls to the gateway", "GATEWAY_TLS_CERT_FILE", "GATEWAY_TLS_KEY_FILE", "GATEWAY_TLS_CA_FILE"},
	} {
		f := tlsreload.Files{Cert: d.get(tls.cert), Key: d.get(tls.key), CA: d.get(tls.ca)}
		if f.Cert == "" && f.Key == "" && f.CA == "" {
			continue
		}
		if _, err := tlsreload.New(f); err != nil {
			problems = append(problems, "mutual TLS of the "+tls.what+": "+err.Error())
		} else {
			by["mutual TLS"] = append(by["mutual TLS"], tls.what)
		}
	}
	var parts []string
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+": "+strings.Join(by[k], ", "))
	}
	detail := strings.Join(parts, "; ")
	if detail == "" {
		detail = "no secret settings in this environment"
	}
	if len(problems) > 0 {
		return Result{Status: Fail, Detail: strings.Join(problems, "; "),
			Hint: "check the file paths and permissions, VAULT_ADDR and the token's policy"}
	}
	res := Result{Status: OK, Detail: detail}
	if len(by["env"]) > 0 {
		res.Hint = "secrets in the environment show in `docker inspect` and process listings: " +
			"NAME_FILE=/run/secrets/name or NAME=vault:<mount>/<path>#<key> keep them out (docs/security/README.md#secrets)"
	}
	return res
}
