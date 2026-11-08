//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/datakey"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

func testContentRing(t *testing.T) *datakey.Keyring {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	keys, err := datakey.ParseLocal("cp-it:" + base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	ring, _ := datakey.NewKeyring(keys...)
	return ring
}

// sealedRow writes a requests row the way the gateway does with a KEK, and
// a legacy row in the clear.
func sealedRow(t *testing.T, h *cpHarness, ring *datakey.Keyring, org uuid.UUID, prompt string) {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256([]byte(prompt))
	sha := hex.EncodeToString(sum[:])
	store := datakey.NewStore(ring)
	err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		dek, err := store.Active(ctx, tx, org)
		if err != nil {
			return err
		}
		sealed, err := dek.Seal(prompt, datakey.ContentAAD(org, "request_content", sha))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO requests (org_id, action, request_sha256, request_content, created_at)
			VALUES ($1, 'allow', $2, $3, NOW())`, org, sha, sealed); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO requests (org_id, action, request_content, created_at)
			VALUES ($1, 'block', 'legacy plain text', NOW() - interval '1 minute')`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func requestRows(t *testing.T, h *cpHarness, org uuid.UUID, token string) []map[string]any {
	t.Helper()
	status, body := h.do("GET", "/v1/organizations/"+org.String()+"/requests", token, "")
	if status != 200 {
		t.Fatalf("status %d: %v", status, body)
	}
	var out []map[string]any
	for _, r := range body["data"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestRequestsContentDecryption(t *testing.T) {
	ring := testContentRing(t)
	const prompt = `{"messages":[{"role":"user","content":"bí mật khách hàng"}]}`

	t.Run("with the key: plain text", func(t *testing.T) {
		h := newCPHarness(t, func(s *appSettings) { s.contentKeys = datakey.NewStore(ring) })
		org, _, admin := h.org(auth.RoleAdmin)
		sealedRow(t, h, ring, org, prompt)
		rows := requestRows(t, h, org, admin)
		if len(rows) != 2 || rows[0]["request_content"] != prompt || rows[0]["content_error"] != nil {
			t.Fatalf("sealed row: %v", rows)
		}
		if rows[1]["request_content"] != "legacy plain text" {
			t.Errorf("legacy row: %v", rows[1])
		}
	})

	t.Run("without a key: hidden with a reason", func(t *testing.T) {
		h := newCPHarness(t)
		org, _, admin := h.org(auth.RoleAdmin)
		sealedRow(t, h, ring, org, prompt)
		rows := requestRows(t, h, org, admin)
		if _, ok := rows[0]["request_content"]; ok || rows[0]["content_error"] == nil {
			t.Fatalf("sealed row shown without a key: %v", rows[0])
		}
		if rows[1]["request_content"] != "legacy plain text" {
			t.Errorf("legacy row: %v", rows[1])
		}
	})

	t.Run("another KEK: hidden, not an error page", func(t *testing.T) {
		h := newCPHarness(t, func(s *appSettings) { s.contentKeys = datakey.NewStore(testContentRing(t)) })
		org, _, admin := h.org(auth.RoleAdmin)
		sealedRow(t, h, ring, org, prompt)
		rows := requestRows(t, h, org, admin)
		if _, ok := rows[0]["request_content"]; ok || rows[0]["content_error"] == nil {
			t.Fatalf("row: %v", rows[0])
		}
	})
}
