// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/datakey"
)

// contentField is one stored body of a requests row.
type contentField struct {
	value  **string
	column string
	sha256 *string
}

// openContent replaces sealed content with its plain text, in the
// organization's transaction. Content that cannot be opened is removed from
// the answer, and the reason returned for content_error: there is no key
// configured, the data key was destroyed, or the value does not decrypt.
func openContent(ctx context.Context, tx pgx.Tx, keys *datakey.Store, org uuid.UUID, fields ...contentField) string {
	reason := ""
	for _, f := range fields {
		v := *f.value
		if v == nil || !datakey.IsSealed(*v) {
			continue
		}
		if keys == nil {
			*f.value = nil
			reason = "encrypted: this control plane has no key-encryption key (CONTENT_KEK, CONTENT_KEK_FILE or CONTENT_KEK_VAULT_KEY)"
			continue
		}
		sha := ""
		if f.sha256 != nil {
			sha = *f.sha256
		}
		plain, err := keys.Open(ctx, tx, org, *v, datakey.ContentAAD(org, f.column, sha))
		switch {
		case err == nil:
			*f.value = &plain
		case errors.Is(err, datakey.ErrKeyDestroyed):
			*f.value = nil
			reason = "encrypted with a data key that was destroyed"
		default:
			slog.Error("stored content does not decrypt", "org", org, "column", f.column, "err", err)
			*f.value = nil
			reason = "encrypted, and it does not decrypt with the configured keys"
		}
	}
	return reason
}
