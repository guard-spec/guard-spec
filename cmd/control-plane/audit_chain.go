// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The activity log is a hash chain per organization, and one for the
// instance rows (migration 022): the database chains every insert, and this
// file checks the chains and signs their heads.
//
//	hash = SHA-256(prev_hash || canonical(row))
//
// canonical is computed here, independently of the database's
// activity_log_canonical, from the row's fields: a changed function in the
// database does not change what verify expects.

// zeroHash is the prev_hash of a chain's first row.
var zeroHash = make([]byte, 32)

// chainRow is one activity_log row as verify reads it.
type chainRow struct {
	Seq        int64
	ID         uuid.UUID
	Org        *uuid.UUID
	At         string // UTC, microseconds, as the database formats it
	Actor      *uuid.UUID
	ActorEmail *string
	Action     string
	Target     *string
	IP         *string
	Details    string // jsonb as text
	PrevHash   []byte
	Hash       []byte
}

// canonical is the text the row's hash covers: each field length-prefixed.
func (r chainRow) canonical() string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	id := func(p *uuid.UUID) string {
		if p == nil {
			return ""
		}
		return p.String()
	}
	fields := []string{"guard-spec/activity/v1", strconv.FormatInt(r.Seq, 10), r.ID.String(), id(r.Org), r.At,
		id(r.Actor), str(r.ActorEmail), r.Action, str(r.Target), str(r.IP), r.Details}
	var b strings.Builder
	for _, f := range fields {
		// length() of a Postgres text counts characters.
		b.WriteString(strconv.Itoa(len([]rune(f))))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

func (r chainRow) want() []byte {
	h := sha256.New()
	h.Write(r.PrevHash)
	h.Write([]byte(r.canonical()))
	return h.Sum(nil)
}

const chainSelect = `SELECT seq, id, org_id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
	actor_id, actor_email, action, target, ip, details::text, prev_hash, hash FROM activity_log`

// chainBreak is the first problem verify found in a chain.
type chainBreak struct {
	Seq    int64
	Reason string
}

// chainReport is the outcome for one chain.
type chainReport struct {
	Org      *uuid.UUID
	First    int64 // the first row's seq (above 1: older rows went with retention)
	Last     int64
	Rows     int64
	Anchors  int
	Break    *chainBreak
	Unsigned int // anchors whose signature could not be checked (no key given)
}

func chainName(org *uuid.UUID) string {
	if org == nil {
		return "instance"
	}
	return "org " + org.String()
}

// verifyChain reads one chain in order and checks seq, links and hashes,
// then its anchors.
func verifyChain(ctx context.Context, db *pgxpool.Pool, org *uuid.UUID, pub ed25519.PublicKey) (chainReport, error) {
	rep := chainReport{Org: org}
	where, args := " WHERE org_id IS NULL", []any{}
	if org != nil {
		where, args = " WHERE org_id = $1", []any{*org}
	}
	rows, err := db.Query(ctx, chainSelect+where+" ORDER BY seq", args...)
	if err != nil {
		return rep, err
	}
	defer rows.Close()
	var prev []byte
	heads := map[int64][]byte{}
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.Seq, &r.ID, &r.Org, &r.At, &r.Actor, &r.ActorEmail, &r.Action, &r.Target, &r.IP,
			&r.Details, &r.PrevHash, &r.Hash); err != nil {
			return rep, err
		}
		rep.Rows++
		heads[r.Seq] = r.Hash
		if rep.Break != nil {
			rep.Last = r.Seq
			continue
		}
		switch {
		case rep.Rows == 1:
			rep.First = r.Seq
			if r.Seq == 1 && !bytes.Equal(r.PrevHash, zeroHash) {
				rep.Break = &chainBreak{r.Seq, "the first row does not start the chain"}
			}
		case r.Seq != rep.Last+1:
			rep.Break = &chainBreak{rep.Last + 1, fmt.Sprintf("rows %d to %d are missing", rep.Last+1, r.Seq-1)}
		case !bytes.Equal(r.PrevHash, prev):
			rep.Break = &chainBreak{r.Seq, "prev_hash is not the previous row's hash (a row before it was changed or replaced)"}
		}
		if rep.Break == nil && !bytes.Equal(r.Hash, r.want()) {
			rep.Break = &chainBreak{r.Seq, "the row does not match its hash (it was changed)"}
		}
		prev, rep.Last = r.Hash, r.Seq
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	return rep, checkAnchors(ctx, db, org, pub, heads, &rep)
}

// anchorMessage is what an anchor's signature covers.
func anchorMessage(org *uuid.UUID, seq int64, hash []byte, at time.Time) []byte {
	return []byte("guard-spec/audit-anchor/v1\n" + chainName(org) + "\n" + strconv.FormatInt(seq, 10) + "\n" +
		hex.EncodeToString(hash) + "\n" + at.UTC().Format(time.RFC3339Nano))
}

func checkAnchors(ctx context.Context, db *pgxpool.Pool, org *uuid.UUID, pub ed25519.PublicKey, heads map[int64][]byte, rep *chainReport) error {
	where, args := " WHERE org_id IS NULL", []any{}
	if org != nil {
		where, args = " WHERE org_id = $1", []any{*org}
	}
	rows, err := db.Query(ctx, `SELECT seq, hash, at, key_id, signature FROM audit_anchors`+where+` ORDER BY seq`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var hash, sig []byte
		var at time.Time
		var keyID string
		if err := rows.Scan(&seq, &hash, &at, &keyID, &sig); err != nil {
			return err
		}
		rep.Anchors++
		if pub == nil {
			rep.Unsigned++
		} else if !ed25519.Verify(pub, anchorMessage(org, seq, hash, at), sig) {
			rep.setBreak(seq, fmt.Sprintf("anchor at seq %d: the signature does not verify with key %s (forged or another key)", seq, keyIDOf(pub)))
			continue
		}
		switch got, ok := heads[seq]; {
		case seq < rep.First:
			// The row went with retention.
		case !ok:
			rep.setBreak(seq, fmt.Sprintf("anchor at seq %d: the row is gone (the chain was cut after it)", seq))
		case !bytes.Equal(got, hash):
			rep.setBreak(seq, fmt.Sprintf("anchor at seq %d: the row's hash differs from the signed one (the chain was rewritten)", seq))
		}
	}
	return rows.Err()
}

func (rep *chainReport) setBreak(seq int64, reason string) {
	if rep.Break == nil || seq < rep.Break.Seq {
		rep.Break = &chainBreak{seq, reason}
	}
}

// ── Signing ─────────────────────────────────────────────────────────────────

// parseSigningKey reads AUDIT_SIGNING_KEY: an Ed25519 seed, 32 bytes in
// base64 (openssl rand -base64 32).
func parseSigningKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, errors.New("AUDIT_SIGNING_KEY must be 32 random bytes in base64 (openssl rand -base64 32)")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// parsePublicKey reads AUDIT_VERIFY_KEY: the public key, 32 bytes in base64
// (what `control-plane audit public-key` prints).
func parsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("the public key must be 32 bytes in base64")
	}
	return ed25519.PublicKey(raw), nil
}

// keyIDOf names a key: the first 8 bytes of its SHA-256, in hex.
func keyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// anchorHeads signs the head of every chain that moved since its last anchor
// and stores the anchors; each is also logged, so a copy lives outside the
// database. It returns how many it made.
func anchorHeads(ctx context.Context, db *pgxpool.Pool, key ed25519.PrivateKey) (int, error) {
	rows, err := db.Query(ctx, `SELECT org_id, seq, hash FROM activity_chain_heads()`)
	if err != nil {
		return 0, err
	}
	type head struct {
		org  *uuid.UUID
		seq  int64
		hash []byte
	}
	var heads []head
	for rows.Next() {
		var h head
		if err := rows.Scan(&h.org, &h.seq, &h.hash); err != nil {
			rows.Close()
			return 0, err
		}
		heads = append(heads, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	pub := key.Public().(ed25519.PublicKey)
	id := keyIDOf(pub)
	for _, h := range heads {
		at := time.Now().UTC().Truncate(time.Microsecond)
		sig := ed25519.Sign(key, anchorMessage(h.org, h.seq, h.hash, at))
		if _, err := db.Exec(ctx, `SELECT insert_audit_anchor($1, $2, $3, $4, $5, $6)`, h.org, h.seq, h.hash, at, id, sig); err != nil {
			return 0, err
		}
		slog.Info("audit anchor", "chain", chainName(h.org), "seq", h.seq, "hash", hex.EncodeToString(h.hash),
			"at", at.Format(time.RFC3339Nano), "key_id", id, "signature", base64.StdEncoding.EncodeToString(sig))
	}
	return len(heads), nil
}

// runAnchoring signs the chain heads every interval until ctx ends.
func runAnchoring(ctx context.Context, db *pgxpool.Pool, key ed25519.PrivateKey, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if n, err := anchorHeads(ctx, db, key); err != nil {
			slog.Warn("audit anchoring failed", "err", err)
		} else if n > 0 {
			slog.Info("audit anchors written", "chains", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ── control-plane audit ─────────────────────────────────────────────────────

const auditUsage = `usage: control-plane audit <command> [flags]

The activity log's hash chains (docs/security/README.md#audit-log-integrity).
DATABASE_URL must name a role that bypasses row-level security (the table
owner).

commands:
  verify      check every chain (or -org): order, links, hashes, and the
              signed anchors (with AUDIT_SIGNING_KEY, AUDIT_VERIFY_KEY or
              -key); exit 1 at the first break, which it names
  anchor      sign the chain heads now (AUDIT_SIGNING_KEY)
  export      print -org's rows and anchors as JSON lines, for an auditor
  public-key  print the public key of AUDIT_SIGNING_KEY (AUDIT_VERIFY_KEY)

flags:`

func runAudit(ctx context.Context, args []string, getenv func(string) string, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, auditUsage)
		return 2
	}
	cmd := args[0]
	fset := flag.NewFlagSet("audit "+cmd, flag.ContinueOnError)
	fset.SetOutput(errOut)
	orgFlag := fset.String("org", "", "one organization's chain (verify, export); export requires it")
	keyFlag := fset.String("key", "", "public key to check anchors with (default: AUDIT_VERIFY_KEY, else from AUDIT_SIGNING_KEY)")
	fset.Usage = func() { _, _ = fmt.Fprintln(errOut, auditUsage); fset.PrintDefaults() }
	if err := fset.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int { _, _ = fmt.Fprintln(errOut, "error:", err); return 2 }
	var signing ed25519.PrivateKey
	if s := getenv("AUDIT_SIGNING_KEY"); s != "" {
		k, err := parseSigningKey(s)
		if err != nil {
			return fail(err)
		}
		signing = k
	}
	if cmd == "public-key" {
		if signing == nil {
			return fail(errors.New("AUDIT_SIGNING_KEY is not set"))
		}
		pub := signing.Public().(ed25519.PublicKey)
		_, _ = fmt.Fprintf(out, "%s  (key id %s)\n", base64.StdEncoding.EncodeToString(pub), keyIDOf(pub))
		return 0
	}
	var org *uuid.UUID
	if *orgFlag != "" {
		id, err := uuid.Parse(*orgFlag)
		if err != nil {
			return fail(fmt.Errorf("-org: %w", err))
		}
		org = &id
	}
	var pub ed25519.PublicKey
	switch {
	case *keyFlag != "":
		k, err := parsePublicKey(*keyFlag)
		if err != nil {
			return fail(err)
		}
		pub = k
	case getenv("AUDIT_VERIFY_KEY") != "":
		k, err := parsePublicKey(getenv("AUDIT_VERIFY_KEY"))
		if err != nil {
			return fail(fmt.Errorf("AUDIT_VERIFY_KEY: %w", err))
		}
		pub = k
	case signing != nil:
		pub = signing.Public().(ed25519.PublicKey)
	}
	db, err := pgxpool.New(ctx, getenv("DATABASE_URL"))
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	var bypass bool
	if err := db.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		return fail(err)
	}
	if !bypass {
		return fail(errors.New("DATABASE_URL must name a role that bypasses row-level security (the table owner)"))
	}
	switch cmd {
	case "verify":
		return auditVerify(ctx, db, org, pub, out, errOut)
	case "anchor":
		if signing == nil {
			return fail(errors.New("AUDIT_SIGNING_KEY is not set"))
		}
		n, err := anchorHeads(ctx, db, signing)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%d anchors written (key id %s)\n", n, keyIDOf(signing.Public().(ed25519.PublicKey)))
		return 0
	case "export":
		if org == nil {
			return fail(errors.New("export needs -org"))
		}
		if err := auditExport(ctx, db, *org, out); err != nil {
			return fail(err)
		}
		return 0
	default:
		fset.Usage()
		return 2
	}
}

func auditVerify(ctx context.Context, db *pgxpool.Pool, org *uuid.UUID, pub ed25519.PublicKey, out, errOut io.Writer) int {
	var chains []*uuid.UUID
	if org != nil {
		chains = []*uuid.UUID{org}
	} else {
		rows, err := db.Query(ctx, `SELECT DISTINCT org_id FROM activity_log ORDER BY org_id NULLS FIRST`)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 2
		}
		for rows.Next() {
			var o *uuid.UUID
			if err := rows.Scan(&o); err != nil {
				rows.Close()
				_, _ = fmt.Fprintln(errOut, "error:", err)
				return 2
			}
			chains = append(chains, o)
		}
		rows.Close()
	}
	broken := 0
	for _, o := range chains {
		rep, err := verifyChain(ctx, db, o, pub)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 2
		}
		status := "ok"
		if rep.Break != nil {
			broken++
			status = fmt.Sprintf("BROKEN at seq %d: %s", rep.Break.Seq, rep.Break.Reason)
		}
		note := ""
		if rep.First > 1 {
			note += fmt.Sprintf(", rows before %d removed by retention", rep.First)
		}
		if rep.Unsigned > 0 {
			note += fmt.Sprintf(", %d anchors not checked (no public key)", rep.Unsigned)
		}
		_, _ = fmt.Fprintf(out, "%s: %d rows (seq %d-%d), %d anchors%s: %s\n", chainName(o), rep.Rows, rep.First, rep.Last, rep.Anchors, note, status)
	}
	if broken > 0 {
		_, _ = fmt.Fprintf(out, "%d of %d chains broken\n", broken, len(chains))
		return 1
	}
	_, _ = fmt.Fprintf(out, "%d chains verified\n", len(chains))
	return 0
}

// auditExport prints an org's rows, then its anchors, one JSON object a line.
func auditExport(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, out io.Writer) error {
	enc := json.NewEncoder(out)
	rows, err := db.Query(ctx, chainSelect+` WHERE org_id = $1 ORDER BY seq`, org)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.Seq, &r.ID, &r.Org, &r.At, &r.Actor, &r.ActorEmail, &r.Action, &r.Target, &r.IP,
			&r.Details, &r.PrevHash, &r.Hash); err != nil {
			rows.Close()
			return err
		}
		_ = enc.Encode(map[string]any{"kind": "activity", "seq": r.Seq, "id": r.ID, "org_id": r.Org, "at": r.At,
			"actor_id": r.Actor, "actor_email": r.ActorEmail, "action": r.Action, "target": r.Target, "ip": r.IP,
			"details": json.RawMessage(r.Details), "prev_hash": hex.EncodeToString(r.PrevHash), "hash": hex.EncodeToString(r.Hash)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	anchors, err := db.Query(ctx, `SELECT seq, hash, at, key_id, signature FROM audit_anchors WHERE org_id = $1 ORDER BY seq`, org)
	if err != nil {
		return err
	}
	defer anchors.Close()
	for anchors.Next() {
		var seq int64
		var hash, sig []byte
		var at time.Time
		var keyID string
		if err := anchors.Scan(&seq, &hash, &at, &keyID, &sig); err != nil {
			return err
		}
		_ = enc.Encode(map[string]any{"kind": "anchor", "seq": seq, "hash": hex.EncodeToString(hash),
			"at": at.UTC().Format(time.RFC3339Nano), "key_id": keyID, "signature": base64.StdEncoding.EncodeToString(sig),
			"message": string(anchorMessage(&org, seq, hash, at))})
	}
	return anchors.Err()
}

