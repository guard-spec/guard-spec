-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

DROP FUNCTION IF EXISTS insert_audit_anchor(UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, BYTEA);
DROP FUNCTION IF EXISTS activity_chain_heads();
DROP TABLE IF EXISTS audit_anchors;
CREATE OR REPLACE FUNCTION purge_activity_rows(cutoff TIMESTAMPTZ, batch INT)
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    IF batch IS NULL OR batch < 1 OR batch > 100000 THEN
        RAISE EXCEPTION 'batch must be between 1 and 100000';
    END IF;
    DELETE FROM activity_log WHERE id IN (
        SELECT id FROM activity_log WHERE at < cutoff
        ORDER BY at LIMIT batch
        FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
GRANT UPDATE, DELETE ON activity_log TO guardspec_app;
DROP TRIGGER IF EXISTS activity_log_chain ON activity_log;
DROP FUNCTION IF EXISTS activity_log_chain();
DROP INDEX IF EXISTS activity_log_instance_chain;
DROP INDEX IF EXISTS activity_log_org_chain;
ALTER TABLE activity_log DROP COLUMN IF EXISTS hash, DROP COLUMN IF EXISTS prev_hash, DROP COLUMN IF EXISTS seq;
DROP FUNCTION IF EXISTS activity_log_canonical(activity_log);
ALTER TABLE org_security DROP COLUMN IF EXISTS content_view_reason, DROP COLUMN IF EXISTS content_read_role;
