-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Content encryption (RF-771f82ec). With a key-encryption key configured
-- (CONTENT_KEK, CONTENT_KEK_FILE or a Vault Transit key), stored prompt and
-- response content is sealed with its organization's data key (AES-256-GCM)
-- and written as "gsenc:v1:<key id>:<base64>" in requests.request_content and
-- response_content. This table holds the data keys, only wrapped by the KEK
-- (kek_id names it); the KEK itself is never stored.
--
-- One key per organization is active and seals new content; retired keys
-- stay until no row uses them (`control-plane keys prune`, and retention).
-- Deleting the organization deletes its keys, so what is left of its
-- content, anywhere the key is gone, no longer decrypts.
CREATE TABLE org_data_keys (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kek_id       TEXT NOT NULL CONSTRAINT org_data_keys_kek_id CHECK (char_length(kek_id) BETWEEN 1 AND 200),
    wrapped      BYTEA NOT NULL CONSTRAINT org_data_keys_wrapped CHECK (octet_length(wrapped) BETWEEN 16 AND 4096),
    active       BOOL NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at   TIMESTAMPTZ,
    rewrapped_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX org_data_keys_one_active ON org_data_keys (org_id) WHERE active;
CREATE INDEX idx_org_data_keys_org ON org_data_keys (org_id, created_at);

ALTER TABLE org_data_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_org_data_keys ON org_data_keys
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE ON org_data_keys TO guardspec_app;

-- Retention: retired keys that no stored row names any more, of every
-- organization (RLS does not let guardspec_app see them all), so the batch
-- runs with the owner's rights, like purge_audit_rows.
CREATE FUNCTION purge_unused_data_keys()
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    DELETE FROM org_data_keys k
    WHERE NOT k.active
      AND NOT EXISTS (
        SELECT 1 FROM requests r
        WHERE r.org_id = k.org_id
          AND (r.request_content LIKE 'gsenc:v1:' || k.id::text || ':%'
            OR r.response_content LIKE 'gsenc:v1:' || k.id::text || ':%'));
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION purge_unused_data_keys() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_unused_data_keys() TO guardspec_app;
