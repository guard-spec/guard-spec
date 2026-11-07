-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Shared scan cache (RF-2bbaa64e): with SCAN_CACHE_BACKEND=postgres, gateway
-- replicas share the detector results of texts that every request of a
-- session sends again (system prompt, tool definitions, earlier tool results
-- and documents), so a session survives a restart or a move to another
-- replica without classifying its whole history again.
--
-- A row holds one text's scores and verdict metadata and the model identity
-- they were computed with (value), never the text: key is a SHA-256 of the
-- org, the kind, the full content and the model identity
-- (cmd/gateway/scan_cache_shared.go). Rows are only read before expires_at
-- (SCAN_CACHE TTL, 6 hours); the control plane's retention job deletes
-- expired rows (purge_scan_cache), and an org's rows go with the org.
--
-- Row level security by org like every tenant table: the key already covers
-- the org, but RLS also keeps a replica serving one org from reading or
-- overwriting another org's rows with a key it should not have.

CREATE TABLE scan_cache (
    key        BYTEA PRIMARY KEY CONSTRAINT scan_cache_key_len CHECK (octet_length(key) = 32),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    value      JSONB NOT NULL CONSTRAINT scan_cache_value_size CHECK (pg_column_size(value) <= 65536),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_scan_cache_expires ON scan_cache (expires_at);
CREATE INDEX idx_scan_cache_org ON scan_cache (org_id);

ALTER TABLE scan_cache ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_scan_cache ON scan_cache
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_cache TO guardspec_app;

-- Expired rows of every org, in batches, with the owner's rights (like
-- purge_audit_rows): guardspec_app keeps no way around RLS. Returns how many
-- rows it removed.
CREATE FUNCTION purge_scan_cache(batch INT)
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    IF batch IS NULL OR batch < 1 OR batch > 100000 THEN
        RAISE EXCEPTION 'batch must be between 1 and 100000';
    END IF;
    DELETE FROM scan_cache WHERE key IN (
        SELECT key FROM scan_cache WHERE expires_at < now()
        ORDER BY expires_at LIMIT batch
        FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION purge_scan_cache(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_scan_cache(INT) TO guardspec_app;
