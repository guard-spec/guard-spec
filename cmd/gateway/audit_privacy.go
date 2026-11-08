package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/datakey"
)

// auditDigest is what an audit row keeps of a request or response body. The
// content itself is only written when storage is enabled (decision D6).
type auditDigest struct {
	SHA256  *string
	Bytes   *int
	Content *string // kept for the insert, which drops it unless storage is on
}

// digest hashes body. An empty body, such as a streamed response that was not
// buffered, yields NULL columns.
func digest(body string) auditDigest {
	if body == "" {
		return auditDigest{}
	}
	sum := sha256.Sum256([]byte(body))
	h := hex.EncodeToString(sum[:])
	n := len(body)
	// A TEXT column rejects NUL and invalid UTF-8, which would lose the whole row.
	content := strings.ReplaceAll(strings.ToValidUTF8(body, "�"), "\x00", "�")
	return auditDigest{SHA256: &h, Bytes: &n, Content: &content}
}

// auditInsert writes one requests row. pii_entities ($13) holds the output
// guard counts. Content is stored only when the gateway enables it for every
// org ($14) or the row's organization has opted in. route_target ($21) is the
// named upstream (migration 011); repeat_count ($23) the number of retried
// refusals the row stands for (migration 019, audit_dedupe.go).
const auditInsert = `
INSERT INTO requests
	(id, org_id, project_id, model, action, rule_id, injection_label, injection_score,
	 toxicity_score, anomaly_score, had_tag_chars, had_bidi, latency_ms, pii_entities,
	 request_sha256, request_bytes, request_content,
	 response_sha256, response_bytes, response_content, route_target, repeat_count)
VALUES (COALESCE($22, gen_random_uuid()), $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
	$15, $16, CASE WHEN ` + storeContent + ` THEN $17::text END,
	$18, $19, CASE WHEN ` + storeContent + ` THEN $20::text END, $21, $23)`

const storeContent = `($14::bool OR COALESCE(
	(SELECT o.audit_store_content FROM organizations o WHERE o.id = $1), false))`

// auditContent says whether audit rows keep content and how it is sealed.
type auditContent struct {
	all  bool           // AUDIT_STORE_CONTENT: every org stores content
	keys *datakey.Store // nil: content is stored in the clear
}

// sealSafe runs seal in a savepoint. When sealing fails (the KEK service is
// down, say) the row is still written, without its content: content is never
// stored in the clear when keys are configured.
func (c auditContent) sealSafe(ctx context.Context, tx pgx.Tx, org uuid.UUID, req, resp *auditDigest) error {
	if c.keys == nil || (req.Content == nil && resp.Content == nil) {
		return nil
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := c.seal(ctx, sp, org, req, resp); err != nil {
		_ = sp.Rollback(ctx)
		slog.Error("content encryption failed: the request is logged without its content", "org", org, "err", err)
		req.Content, resp.Content = nil, nil
		return nil
	}
	return sp.Commit(ctx)
}

// seal replaces the content of req and resp with values sealed by the org's
// data key, inside the transaction that writes the row. It does nothing
// without keys or content, and drops the content when the row will not store
// it (the org has not opted in), so no data key is made for orgs that never
// store content.
func (c auditContent) seal(ctx context.Context, tx pgx.Tx, org uuid.UUID, req, resp *auditDigest) error {
	if c.keys == nil || (req.Content == nil && resp.Content == nil) {
		return nil
	}
	store := c.all
	if !store {
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT audit_store_content FROM organizations WHERE id = $1), false)`, org).Scan(&store); err != nil {
			return err
		}
	}
	if !store {
		req.Content, resp.Content = nil, nil
		return nil
	}
	dek, err := c.keys.Active(ctx, tx, org)
	if err != nil {
		return err
	}
	for _, x := range []struct {
		d   *auditDigest
		col string
	}{{req, "request_content"}, {resp, "response_content"}} {
		if x.d.Content == nil {
			continue
		}
		sealed, err := dek.Seal(*x.d.Content, datakey.ContentAAD(org, x.col, *x.d.SHA256))
		if err != nil {
			return err
		}
		x.d.Content = &sealed
	}
	return nil
}
