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

// auditInsert writes one requests row. Content is stored only when the gateway
// enables it for everyone ($13) or the row's organization has opted in.
const auditInsert = `
INSERT INTO requests
	(org_id, project_id, model, action, rule_id, injection_label, injection_score,
	 toxicity_score, anomaly_score, had_tag_chars, had_bidi, latency_ms,
	 request_sha256, request_bytes, request_content,
	 response_sha256, response_bytes, response_content)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
	$14, $15, CASE WHEN ` + storeContent + ` THEN $16::text END,
	$17, $18, CASE WHEN ` + storeContent + ` THEN $19::text END)`

const storeContent = `($13::bool OR COALESCE(
	(SELECT o.audit_store_content FROM organizations o WHERE o.id = $1), false))`
