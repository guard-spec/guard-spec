// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/guard-spec/guard-spec/internal/datakey"
)

// checkEncryption reports whether stored content is encrypted: the
// key-encryption key is configured and works (a wrap and unwrap round trip,
// which also reaches Vault), every data key in the database names a
// configured KEK, and no content is stored in the clear. With the
// application role the database sees one organization at a time, so the
// counts are complete only with an owner DATABASE_URL.
func (d *doctor) checkEncryption(ctx context.Context) Result {
	ring, err := datakey.FromEnv(d.get)
	if err != nil {
		return Result{Status: Fail, Detail: err.Error()}
	}
	storeAll := strings.EqualFold(strings.TrimSpace(d.get("AUDIT_STORE_CONTENT")), "true")
	if ring == nil {
		r := Result{Status: OK, Detail: "no key-encryption key; content storage is off (AUDIT_STORE_CONTENT)"}
		orgs := d.countOrgsStoringContent(ctx)
		if storeAll || orgs > 0 {
			what := "AUDIT_STORE_CONTENT=true"
			if !storeAll {
				what = plural(orgs, "organization") + " store content"
			}
			r = Result{Status: Warn, Detail: what + ", and prompts and answers are stored in the clear",
				Hint: "set CONTENT_KEK (openssl rand -base64 32), CONTENT_KEK_FILE or CONTENT_KEK_VAULT_KEY on the gateway and the control plane, " +
					"then run control-plane keys encrypt-existing (docs/security/README.md#encryption)"}
		}
		return r
	}
	kek := ring.Active()
	probe := make([]byte, 32)
	_, _ = rand.Read(probe)
	cctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	wrapped, err := kek.Wrap(cctx, probe, []byte("guard-spec/doctor"))
	if err == nil {
		var back []byte
		if back, err = kek.Unwrap(cctx, wrapped, []byte("guard-spec/doctor")); err == nil && !bytes.Equal(back, probe) {
			err = fmt.Errorf("unwrap returned another key")
		}
	}
	if err != nil {
		return Result{Status: Fail, Detail: fmt.Sprintf("the active key-encryption key %s does not work: %v", kek.ID(), err),
			Hint: "check the key, or Vault's address, token and the transit key's policy (encrypt and decrypt)"}
	}
	detail := fmt.Sprintf("content is sealed with each organization's data key; active KEK %s works", kek.ID())
	if d.conn == nil {
		return Result{Status: OK, Detail: detail + " (database not checked)"}
	}
	var unknown []string
	rows, err := d.conn.Query(ctx, `SELECT DISTINCT kek_id FROM org_data_keys`)
	if err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				if _, ok := ring.Get(id); !ok {
					unknown = append(unknown, id)
				}
			}
		}
		rows.Close()
	}
	if len(unknown) > 0 {
		return Result{Status: Fail, Detail: "data keys are wrapped by " + strings.Join(unknown, ", ") + ", which is not configured: their content cannot be read",
			Hint: "configure that key too (CONTENT_KEK takes several, the active one first), then run control-plane keys rotate"}
	}
	var plain int64
	if err := d.conn.QueryRow(ctx, `SELECT count(*) FROM requests WHERE (request_content IS NOT NULL AND request_content NOT LIKE 'gsenc:v1:%')
		OR (response_content IS NOT NULL AND response_content NOT LIKE 'gsenc:v1:%')`).Scan(&plain); err == nil && plain > 0 {
		return Result{Status: Warn, Detail: detail + fmt.Sprintf("; %s still stored in the clear", plural(int(plain), "row")),
			Hint: "run control-plane keys encrypt-existing (with an owner DATABASE_URL)"}
	}
	return Result{Status: OK, Detail: detail}
}

func (d *doctor) countOrgsStoringContent(ctx context.Context) int {
	if d.conn == nil {
		return 0
	}
	var n int
	if err := d.conn.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE audit_store_content`).Scan(&n); err != nil {
		return 0
	}
	return n
}
