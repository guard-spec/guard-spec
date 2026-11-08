// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/datakey"
)

const keysUsage = `usage: control-plane keys <command> [flags]

Manages the keys that encrypt stored content (CONTENT_KEK, CONTENT_KEK_FILE,
CONTENT_KEK_VAULT_KEY) and 2FA secrets (MFA_ENC_KEY). DATABASE_URL must name
a role that bypasses row-level security, such as the table owner; the
services keep running.

commands:
  status            data keys by key-encryption key, sealed and plain stored
                    content, 2FA secrets by MFA key
  rotate            wrap every data key again with the active KEK (the first
                    configured), and seal every 2FA secret again with the
                    first MFA_ENC_KEY; -new-data-keys also starts a new data
                    key per organization
  encrypt-existing  seal the content stored in the clear (rows written before
                    a KEK was configured), in batches
  decrypt-existing  the opposite, before removing the KEK or migrating down
  prune             delete retired data keys that no stored row uses

flags:`

// runKeys is the "keys" subcommand.
func runKeys(ctx context.Context, args []string, getenv func(string) string, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, keysUsage)
		return 2
	}
	cmd := args[0]
	fset := flag.NewFlagSet("keys "+cmd, flag.ContinueOnError)
	fset.SetOutput(errOut)
	batch := fset.Int("batch", 500, "rows per transaction (encrypt-existing, decrypt-existing)")
	newKeys := fset.Bool("new-data-keys", false, "rotate: also start a new data key for every organization")
	orgFlag := fset.String("org", "", "only this organization's data keys and content (2FA secrets are left alone)")
	fset.Usage = func() { _, _ = fmt.Fprintln(errOut, keysUsage); fset.PrintDefaults() }
	if err := fset.Parse(args[1:]); err != nil {
		return 2
	}
	if *batch < 1 || *batch > 10000 {
		_, _ = fmt.Fprintln(errOut, "-batch must be between 1 and 10000")
		return 2
	}
	switch cmd {
	case "status", "rotate", "encrypt-existing", "decrypt-existing", "prune":
	default:
		fset.Usage()
		return 2
	}
	ring, err := datakey.FromEnv(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 2
	}
	// status, prune and a rotation of the 2FA secrets alone need no KEK.
	needsKEK := cmd == "encrypt-existing" || cmd == "decrypt-existing" || (cmd == "rotate" && *newKeys)
	if ring == nil && needsKEK {
		_, _ = fmt.Fprintln(errOut, "error: no key-encryption key: set CONTENT_KEK, CONTENT_KEK_FILE or CONTENT_KEK_VAULT_KEY")
		return 2
	}
	box, err := auth.NewSecretBox(getenv("MFA_ENC_KEY"))
	if err != nil && !errors.Is(err, auth.ErrNoMFAKey) {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 2
	}
	db, err := pgxpool.New(ctx, getenv("DATABASE_URL"))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error: connect:", err)
		return 2
	}
	defer db.Close()
	var bypass bool
	if err := db.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 2
	}
	if !bypass {
		_, _ = fmt.Fprintln(errOut, "error: DATABASE_URL must name a role that bypasses row-level security (the table owner); "+
			"the application role sees one organization at a time")
		return 2
	}
	k := keysCmd{db: db, ring: ring, box: box, out: out, batch: *batch}
	if *orgFlag != "" {
		org, err := uuid.Parse(*orgFlag)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "error: -org:", err)
			return 2
		}
		k.org = &org
	}
	if ring != nil {
		k.store = datakey.NewStore(ring)
	}
	switch cmd {
	case "status":
		err = k.status(ctx)
	case "rotate":
		err = k.rotate(ctx, *newKeys)
	case "encrypt-existing":
		err = k.convert(ctx, true)
	case "decrypt-existing":
		err = k.convert(ctx, false)
	case "prune":
		err = k.prune(ctx)
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	return 0
}

type keysCmd struct {
	db    *pgxpool.Pool
	ring  *datakey.Keyring
	store *datakey.Store
	box   *auth.SecretBox
	out   io.Writer
	batch int
	org   *uuid.UUID // -org: one organization only
}

// orgAnd returns " AND org_id = $n" with the -org argument appended, or
// nothing without -org.
func (k keysCmd) orgAnd(args []any) (string, []any) {
	if k.org == nil {
		return "", args
	}
	args = append(args, *k.org)
	return fmt.Sprintf(" AND org_id = $%d", len(args)), args
}

func (k keysCmd) printf(format string, a ...any) { _, _ = fmt.Fprintf(k.out, format, a...) }

const (
	sealedCond = `(request_content LIKE 'gsenc:v1:%' OR response_content LIKE 'gsenc:v1:%')`
	plainCond  = `((request_content IS NOT NULL AND request_content NOT LIKE 'gsenc:v1:%')
		OR (response_content IS NOT NULL AND response_content NOT LIKE 'gsenc:v1:%'))`
)

func (k keysCmd) status(ctx context.Context) error {
	if k.ring != nil {
		k.printf("key-encryption keys: %s (active: %s)\n", strings.Join(k.ring.IDs(), ", "), k.ring.Active().ID())
	} else {
		k.printf("key-encryption keys: none configured\n")
	}
	f, args := k.orgAnd(nil)
	rows, err := k.db.Query(ctx, `SELECT kek_id, count(*) FILTER (WHERE active), count(*) FILTER (WHERE NOT active)
		FROM org_data_keys WHERE true`+f+` GROUP BY kek_id ORDER BY kek_id`, args...)
	if err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var kek string
		var active, retired int
		if err := rows.Scan(&kek, &active, &retired); err != nil {
			rows.Close()
			return err
		}
		n++
		note := ""
		if k.ring == nil {
			note = " (not configured here)"
		} else if _, ok := k.ring.Get(kek); !ok {
			note = " (NOT CONFIGURED: these keys cannot be opened)"
		} else if kek != k.ring.Active().ID() {
			note = " (run keys rotate to wrap them with the active KEK)"
		}
		k.printf("data keys wrapped by %s: %d active, %d retired%s\n", kek, active, retired, note)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if n == 0 {
		k.printf("data keys: none\n")
	}
	var sealed, plain int64
	if err := k.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE `+sealedCond+`), count(*) FILTER (WHERE `+plainCond+`) FROM requests WHERE true`+f, args...).
		Scan(&sealed, &plain); err != nil {
		return err
	}
	k.printf("stored content: %d rows sealed, %d rows in the clear", sealed, plain)
	if plain > 0 && k.ring != nil {
		k.printf(" (run keys encrypt-existing)")
	}
	k.printf("\n")
	if k.org != nil {
		return nil
	}
	return k.mfaStatus(ctx)
}

func (k keysCmd) mfaStatus(ctx context.Context) error {
	var total int
	if err := k.db.QueryRow(ctx, `SELECT count(*) FROM user_mfa WHERE totp_secret_enc IS NOT NULL OR pending_secret_enc IS NOT NULL`).Scan(&total); err != nil {
		return err
	}
	if k.box == nil {
		k.printf("2FA secrets: %d (MFA_ENC_KEY not set here)\n", total)
		return nil
	}
	byKey := make([]int, k.box.Keys())
	failed := 0
	err := k.eachMFA(ctx, func(_ uuid.UUID, _ string, sealed []byte, idx int, ok bool) error {
		if ok {
			byKey[idx]++
		} else if sealed != nil {
			failed++
		}
		return nil
	})
	if err != nil {
		return err
	}
	parts := []string{}
	for i, c := range byKey {
		parts = append(parts, fmt.Sprintf("key %d: %d", i+1, c))
	}
	k.printf("2FA secrets: %d (%s", total, strings.Join(parts, ", "))
	if failed > 0 {
		k.printf(", %d open with no configured key", failed)
	}
	k.printf(")\n")
	return nil
}

// eachMFA calls fn for every sealed 2FA secret with the index of the key
// that opens it.
func (k keysCmd) eachMFA(ctx context.Context, fn func(user uuid.UUID, column string, sealed []byte, idx int, ok bool) error) error {
	type sec struct {
		user   uuid.UUID
		column string
		sealed []byte
	}
	var all []sec
	rows, err := k.db.Query(ctx, `SELECT user_id, totp_secret_enc, pending_secret_enc FROM user_mfa`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u uuid.UUID
		var t, p []byte
		if err := rows.Scan(&u, &t, &p); err != nil {
			rows.Close()
			return err
		}
		if t != nil {
			all = append(all, sec{u, "totp_secret_enc", t})
		}
		if p != nil {
			all = append(all, sec{u, "pending_secret_enc", p})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range all {
		_, idx, err := k.box.OpenKey(s.sealed, s.user[:])
		if err := fn(s.user, s.column, s.sealed, idx, err == nil); err != nil {
			return err
		}
	}
	return nil
}

func (k keysCmd) rotate(ctx context.Context, newKeys bool) error {
	if k.ring != nil {
		type ref struct{ org, id uuid.UUID }
		var keys []ref
		f, args := k.orgAnd(nil)
		rows, err := k.db.Query(ctx, `SELECT org_id, id FROM org_data_keys WHERE true`+f+` ORDER BY created_at`, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.org, &r.id); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rewrapped := 0
		for _, r := range keys {
			done, err := k.store.Rewrap(ctx, k.db, r.org, r.id)
			if err != nil {
				return fmt.Errorf("data key %s of %s: %w", r.id, r.org, err)
			}
			if done {
				rewrapped++
			}
		}
		k.printf("data keys: %d of %d wrapped again with %s\n", rewrapped, len(keys), k.ring.Active().ID())
		if newKeys {
			var orgs []uuid.UUID
			rows, err := k.db.Query(ctx, `SELECT DISTINCT org_id FROM org_data_keys WHERE active`+f, args...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var o uuid.UUID
				if err := rows.Scan(&o); err != nil {
					rows.Close()
					return err
				}
				orgs = append(orgs, o)
			}
			rows.Close()
			for _, o := range orgs {
				if err := pgx.BeginFunc(ctx, k.db, func(tx pgx.Tx) error {
					_, err := k.store.Rotate(ctx, tx, o)
					return err
				}); err != nil {
					return fmt.Errorf("new data key for %s: %w", o, err)
				}
			}
			k.printf("new data keys: %d organizations (the old keys stay until keys prune finds them unused)\n", len(orgs))
		}
	} else {
		k.printf("data keys: no key-encryption key configured, skipped\n")
	}
	if k.org != nil {
		return nil
	}
	if k.box == nil {
		k.printf("2FA secrets: MFA_ENC_KEY not set, skipped\n")
		return nil
	}
	resealed, failed := 0, 0
	err := k.eachMFA(ctx, func(user uuid.UUID, column string, sealed []byte, idx int, ok bool) error {
		if !ok {
			failed++
			return nil
		}
		if idx == 0 {
			return nil
		}
		plain, err := k.box.Open(sealed, user[:])
		if err != nil {
			return err
		}
		fresh, err := k.box.Seal(plain, user[:])
		if err != nil {
			return err
		}
		// Only if the row still holds what was read: a user who enrolled
		// meanwhile keeps the new secret.
		if _, err := k.db.Exec(ctx, `UPDATE user_mfa SET `+column+` = $2 WHERE user_id = $1 AND `+column+` = $3`, user, fresh, sealed); err != nil {
			return err
		}
		resealed++
		return nil
	})
	if err != nil {
		return err
	}
	k.printf("2FA secrets: %d sealed again with the first MFA_ENC_KEY", resealed)
	if failed > 0 {
		k.printf("; %d open with no configured key (keep the key that sealed them)", failed)
	}
	k.printf("\n")
	if failed == 0 && k.box.Keys() > 1 {
		k.printf("every 2FA secret uses the first MFA_ENC_KEY: the other keys can be removed\n")
	}
	return nil
}

// convert seals the content stored in the clear (seal) or opens the sealed
// content (!seal), batch rows per transaction, until none is left.
func (k keysCmd) convert(ctx context.Context, seal bool) error {
	cond := plainCond
	if !seal {
		cond = sealedCond
	}
	total := 0
	for {
		n := 0
		err := pgx.BeginFunc(ctx, k.db, func(tx pgx.Tx) error {
			type row struct {
				id, org        uuid.UUID
				reqSHA, resSHA *string
				req, res       *string
			}
			var batch []row
			f, args := k.orgAnd([]any{k.batch})
			rows, err := tx.Query(ctx, `SELECT id, org_id, request_sha256, request_content, response_sha256, response_content
				FROM requests WHERE `+cond+f+` ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED`, args...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.org, &r.reqSHA, &r.req, &r.resSHA, &r.res); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, r)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range batch {
				req, err := k.convertValue(ctx, tx, r.org, "request_content", r.reqSHA, r.req, seal)
				if err != nil {
					return fmt.Errorf("row %s: %w", r.id, err)
				}
				res, err := k.convertValue(ctx, tx, r.org, "response_content", r.resSHA, r.res, seal)
				if err != nil {
					return fmt.Errorf("row %s: %w", r.id, err)
				}
				if _, err := tx.Exec(ctx, `UPDATE requests SET request_content = $2, response_content = $3 WHERE id = $1`, r.id, req, res); err != nil {
					return err
				}
			}
			n = len(batch)
			return nil
		})
		if err != nil {
			return err
		}
		total += n
		if n < k.batch {
			break
		}
	}
	if seal {
		k.printf("stored content: %d rows sealed\n", total)
	} else {
		k.printf("stored content: %d rows decrypted (stored in the clear again)\n", total)
	}
	return nil
}

func (k keysCmd) convertValue(ctx context.Context, tx pgx.Tx, org uuid.UUID, column string, sha, v *string, seal bool) (*string, error) {
	if v == nil || datakey.IsSealed(*v) == seal {
		return v, nil
	}
	s := ""
	if sha != nil {
		s = *sha
	}
	aad := datakey.ContentAAD(org, column, s)
	if seal {
		dek, err := k.store.Active(ctx, tx, org)
		if err != nil {
			return nil, err
		}
		out, err := dek.Seal(*v, aad)
		return &out, err
	}
	out, err := k.store.Open(ctx, tx, org, *v, aad)
	return &out, err
}

func (k keysCmd) prune(ctx context.Context) error {
	var n int
	if k.org != nil {
		tag, err := k.db.Exec(ctx, `DELETE FROM org_data_keys k WHERE k.org_id = $1 AND NOT k.active AND NOT EXISTS (
			SELECT 1 FROM requests r WHERE r.org_id = k.org_id
			  AND (r.request_content LIKE 'gsenc:v1:' || k.id::text || ':%' OR r.response_content LIKE 'gsenc:v1:' || k.id::text || ':%'))`, *k.org)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
	} else if err := k.db.QueryRow(ctx, `SELECT purge_unused_data_keys()`).Scan(&n); err != nil {
		return err
	}
	k.printf("data keys: %d retired keys deleted (no stored row used them)\n", n)
	return nil
}
