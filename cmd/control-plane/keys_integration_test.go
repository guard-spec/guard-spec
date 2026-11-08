//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/auth"
)

func randKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func ownerDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	url := envOr("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable")
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, url
}

// keys runs `control-plane keys` with env and returns its exit code and output.
func keys(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runKeys(context.Background(), args, func(k string) string { return env[k] }, &out, &errOut)
	return code, out.String() + errOut.String()
}

// The keys commands on one organization: seal the content stored in the
// clear, move to a new KEK and new data keys, open it again, prune.
func TestKeysCommands(t *testing.T) {
	ctx := context.Background()
	db, url := ownerDB(t)
	org := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO organizations (id, name, slug, audit_store_content) VALUES ($1, 'keys', $2, true)`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	prompts := []string{`{"q":"một"}`, `{"q":"hai"}`, `{"q":"ba"}`}
	for _, p := range prompts {
		sum := sha256.Sum256([]byte(p))
		if _, err := db.Exec(ctx, `INSERT INTO requests (org_id, action, request_sha256, request_content, response_content)
			VALUES ($1, 'allow', $2, $3, 'answer')`, org, hex.EncodeToString(sum[:]), p); err != nil {
			t.Fatal(err)
		}
	}
	k1, k2 := randKey(), randKey()
	env := map[string]string{"DATABASE_URL": url, "CONTENT_KEK": "first:" + k1}
	o := org.String()

	code, out := keys(t, env, "encrypt-existing", "-org", o, "-batch", "2")
	if code != 0 || !strings.Contains(out, "3 rows sealed") {
		t.Fatalf("encrypt-existing: %d %s", code, out)
	}
	var plain, sealed int
	count := func() {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE `+plainCond+`), count(*) FILTER (WHERE `+sealedCond+`)
			FROM requests WHERE org_id = $1`, org).Scan(&plain, &sealed); err != nil {
			t.Fatal(err)
		}
	}
	if count(); plain != 0 || sealed != 3 {
		t.Fatalf("after encrypt: %d plain, %d sealed", plain, sealed)
	}
	if code, out := keys(t, env, "status", "-org", o); code != 0 || !strings.Contains(out, "wrapped by local:first: 1 active, 0 retired") ||
		!strings.Contains(out, "3 rows sealed, 0 rows in the clear") {
		t.Fatalf("status: %d %s", code, out)
	}

	// A new KEK in front: rotate rewraps the data key and starts a new one.
	env["CONTENT_KEK"] = "second:" + k2 + ",first:" + k1
	if code, out := keys(t, env, "rotate", "-org", o, "-new-data-keys"); code != 0 ||
		!strings.Contains(out, "1 of 1 wrapped again with local:second") || !strings.Contains(out, "new data keys: 1") {
		t.Fatalf("rotate: %d %s", code, out)
	}
	// The first KEK can go now.
	env["CONTENT_KEK"] = "second:" + k2
	if code, out := keys(t, env, "status", "-org", o); code != 0 || !strings.Contains(out, "wrapped by local:second: 1 active, 1 retired") {
		t.Fatalf("status after rotate: %d %s", code, out)
	}
	// Retired, but rows use it: prune keeps it.
	if code, out := keys(t, env, "prune", "-org", o); code != 0 || !strings.Contains(out, "0 retired keys deleted") {
		t.Fatalf("prune with rows: %d %s", code, out)
	}
	if code, out := keys(t, env, "decrypt-existing", "-org", o); code != 0 || !strings.Contains(out, "3 rows decrypted") {
		t.Fatalf("decrypt-existing: %d %s", code, out)
	}
	if count(); plain != 3 || sealed != 0 {
		t.Fatalf("after decrypt: %d plain, %d sealed", plain, sealed)
	}
	var got []string
	rows, _ := db.Query(ctx, `SELECT request_content FROM requests WHERE org_id = $1 ORDER BY request_content`, org)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		got = append(got, s)
	}
	rows.Close()
	if strings.Join(got, "|") != `{"q":"ba"}|{"q":"hai"}|{"q":"một"}` {
		t.Fatalf("content after the round trip: %v", got)
	}
	if code, out := keys(t, env, "prune", "-org", o); code != 0 || !strings.Contains(out, "1 retired keys deleted") {
		t.Fatalf("prune: %d %s", code, out)
	}

	// Without the KEK of a data key, nothing is opened or changed.
	env["CONTENT_KEK"] = "other:" + randKey()
	if code, _ := keys(t, env, "encrypt-existing", "-org", o); code != 1 {
		t.Fatalf("encrypt-existing with an unknown KEK: exit %d", code)
	}
	if count(); plain != 3 {
		t.Fatalf("rows changed by a failed run: %d plain", plain)
	}

	// Refused for a role that RLS limits, and without a KEK.
	app := envOr("TEST_DATABASE_URL", "")
	if app != "" {
		if code, out := keys(t, map[string]string{"DATABASE_URL": app, "CONTENT_KEK": k1}, "status"); code != 2 || !strings.Contains(out, "bypasses row-level security") {
			t.Fatalf("app role: %d %s", code, out)
		}
	}
	if code, _ := keys(t, map[string]string{"DATABASE_URL": url}, "encrypt-existing"); code != 2 {
		t.Fatalf("no KEK: exit %d", code)
	}
}

// rotate seals the 2FA secrets of an older MFA_ENC_KEY with the first one;
// secrets of keys it does not have are left alone.
func TestKeysRotateMFA(t *testing.T) {
	ctx := context.Background()
	db, url := ownerDB(t)
	oldKey, newKey := randKey(), randKey()
	oldBox, _ := auth.NewSecretBox(oldKey)
	user := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2)`, user, user.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	sealed, _ := oldBox.Seal([]byte("JBSWY3DPEHPK3PXP"), user[:])
	if _, err := db.Exec(ctx, `INSERT INTO user_mfa (user_id, totp_secret_enc, enabled_at) VALUES ($1, $2, NOW())`, user, sealed); err != nil {
		t.Fatal(err)
	}
	code, out := keys(t, map[string]string{"DATABASE_URL": url, "MFA_ENC_KEY": newKey + "," + oldKey}, "rotate")
	if code != 0 || !strings.Contains(out, "data keys: no key-encryption key configured, skipped") {
		t.Fatalf("rotate: %d %s", code, out)
	}
	var now []byte
	if err := db.QueryRow(ctx, `SELECT totp_secret_enc FROM user_mfa WHERE user_id = $1`, user).Scan(&now); err != nil {
		t.Fatal(err)
	}
	newBox, _ := auth.NewSecretBox(newKey)
	if got, err := newBox.Open(now, user[:]); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("the new key alone does not open the secret: %v", err)
	}
}
