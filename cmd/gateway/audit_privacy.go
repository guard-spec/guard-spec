package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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
// named upstream (migration 011).
const auditInsert = `
INSERT INTO requests
	(id, org_id, project_id, model, action, rule_id, injection_label, injection_score,
	 toxicity_score, anomaly_score, had_tag_chars, had_bidi, latency_ms, pii_entities,
	 request_sha256, request_bytes, request_content,
	 response_sha256, response_bytes, response_content, route_target)
VALUES (COALESCE($22, gen_random_uuid()), $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
	$15, $16, CASE WHEN ` + storeContent + ` THEN $17::text END,
	$18, $19, CASE WHEN ` + storeContent + ` THEN $20::text END, $21)`

const storeContent = `($14::bool OR COALESCE(
	(SELECT o.audit_store_content FROM organizations o WHERE o.id = $1), false))`
