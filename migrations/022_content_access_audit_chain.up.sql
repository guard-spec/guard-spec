-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- RF-aceaddfc: who may read stored content, and an activity log whose
-- changes can be detected.

-- 1. Reading stored prompt and answer content is its own permission: the
-- lowest role allowed (default admin) and whether a reason is required
-- (default yes). Every read is written to the activity log with the reason.
ALTER TABLE org_security
    ADD COLUMN content_read_role TEXT NOT NULL DEFAULT 'admin'
        CONSTRAINT org_security_content_read_role CHECK (content_read_role IN ('viewer', 'member', 'admin', 'owner')),
    ADD COLUMN content_view_reason BOOLEAN NOT NULL DEFAULT TRUE;

-- 2. Hash chain. Each organization's rows, and the instance rows (org_id
-- NULL), form one chain: seq counts up from 1, prev_hash is the previous
-- row's hash (32 zero bytes for the first), and
--   hash = SHA-256(prev_hash || activity_log_canonical(row))
-- A changed, inserted or removed row breaks the chain from there on;
-- `control-plane audit verify` finds the first break, and signed anchors
-- (audit_anchors) catch a chain rewritten from the start or cut at the end.
ALTER TABLE activity_log
    ADD COLUMN seq       BIGINT,
    ADD COLUMN prev_hash BYTEA,
    ADD COLUMN hash      BYTEA;

-- The canonical text of a row: every field, length-prefixed so that no two
-- rows share it. `at` in UTC to the microsecond; details as Postgres prints
-- jsonb (keys sorted by length then bytes, no insignificant spaces).
CREATE FUNCTION activity_log_canonical(a activity_log) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = public, pg_temp
AS $$
    SELECT string_agg(length(v)::text || ':' || v, '' ORDER BY n)
    FROM unnest(ARRAY[
        'guard-spec/activity/v1',
        a.seq::text,
        a.id::text,
        COALESCE(a.org_id::text, ''),
        to_char(a.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        COALESCE(a.actor_id::text, ''),
        COALESCE(a.actor_email, ''),
        a.action,
        COALESCE(a.target, ''),
        COALESCE(a.ip, ''),
        a.details::text
    ]) WITH ORDINALITY AS f(v, n)
$$;

-- Backfill the existing rows, chain by chain, in time order.
DO $$
DECLARE
    r activity_log%ROWTYPE;
    prev BYTEA;
    n BIGINT;
    chain UUID;
    first BOOLEAN := TRUE;
BEGIN
    FOR r IN SELECT * FROM activity_log ORDER BY org_id NULLS FIRST, at, id LOOP
        IF first OR r.org_id IS DISTINCT FROM chain THEN
            chain := r.org_id;
            prev := decode(repeat('00', 32), 'hex');
            n := 0;
            first := FALSE;
        END IF;
        n := n + 1;
        r.seq := n;
        UPDATE activity_log SET seq = n, prev_hash = prev,
            hash = sha256(prev || convert_to(activity_log_canonical(r), 'UTF8'))
        WHERE id = r.id
        RETURNING hash INTO prev;
    END LOOP;
END
$$;

ALTER TABLE activity_log
    ALTER COLUMN seq SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN hash SET NOT NULL;
CREATE UNIQUE INDEX activity_log_org_chain ON activity_log (org_id, seq) WHERE org_id IS NOT NULL;
CREATE UNIQUE INDEX activity_log_instance_chain ON activity_log (seq) WHERE org_id IS NULL;

-- Every insert is chained here, whoever writes it, under a lock per chain so
-- that two writers never take the same place. `at` becomes the time the row
-- takes its place, so time order and chain order agree (retention deletes
-- the oldest rows first and leaves no gap).
CREATE FUNCTION activity_log_chain() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    last_seq BIGINT;
    last_hash BYTEA;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('guard-spec/activity_log/' || COALESCE(NEW.org_id::text, 'instance'), 0));
    IF NEW.org_id IS NULL THEN
        SELECT seq, hash INTO last_seq, last_hash FROM activity_log WHERE org_id IS NULL ORDER BY seq DESC LIMIT 1;
    ELSE
        SELECT seq, hash INTO last_seq, last_hash FROM activity_log WHERE org_id = NEW.org_id ORDER BY seq DESC LIMIT 1;
    END IF;
    NEW.at := clock_timestamp();
    NEW.seq := COALESCE(last_seq, 0) + 1;
    NEW.prev_hash := COALESCE(last_hash, decode(repeat('00', 32), 'hex'));
    NEW.hash := sha256(NEW.prev_hash || convert_to(activity_log_canonical(NEW), 'UTF8'));
    RETURN NEW;
END
$$;
CREATE TRIGGER activity_log_chain BEFORE INSERT ON activity_log
    FOR EACH ROW EXECUTE FUNCTION activity_log_chain();

-- The application only appends. Retention deletes through its function.
REVOKE UPDATE, DELETE ON activity_log FROM guardspec_app;

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
        ORDER BY at, seq LIMIT batch
        FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;

-- 3. Anchors: the head of a chain (seq, hash) signed with the instance's
-- Ed25519 key (AUDIT_SIGNING_KEY) at an interval, and logged. Someone who
-- can rewrite activity_log cannot forge them without the key; a copy of
-- them outside the database (the service log, an export) shows a chain cut
-- at the end.
CREATE TABLE audit_anchors (
    id        BIGSERIAL PRIMARY KEY,
    org_id    UUID REFERENCES organizations(id) ON DELETE CASCADE,
    seq       BIGINT NOT NULL,
    hash      BYTEA NOT NULL CONSTRAINT audit_anchors_hash CHECK (octet_length(hash) = 32),
    at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    key_id    TEXT NOT NULL CONSTRAINT audit_anchors_key_id CHECK (char_length(key_id) BETWEEN 1 AND 64),
    signature BYTEA NOT NULL CONSTRAINT audit_anchors_signature CHECK (octet_length(signature) = 64)
);
CREATE INDEX idx_audit_anchors_chain ON audit_anchors (org_id, seq DESC);
ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit_anchors ON audit_anchors
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY instance_audit_anchors ON audit_anchors
    USING (org_id IS NULL AND current_setting('app.instance_scope', true) = 'on');
GRANT SELECT ON audit_anchors TO guardspec_app;
GRANT USAGE ON SEQUENCE audit_anchors_id_seq TO guardspec_app;

-- The heads of the chains that moved since their last anchor, for the
-- anchoring job (which sees every org only through this function).
CREATE FUNCTION activity_chain_heads()
RETURNS TABLE (org_id UUID, seq BIGINT, hash BYTEA)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT DISTINCT ON (a.org_id) a.org_id, a.seq, a.hash
    FROM activity_log a
    WHERE a.seq > COALESCE((SELECT max(x.seq) FROM audit_anchors x WHERE x.org_id IS NOT DISTINCT FROM a.org_id), 0)
    ORDER BY a.org_id, a.seq DESC
$$;
REVOKE ALL ON FUNCTION activity_chain_heads() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION activity_chain_heads() TO guardspec_app;

CREATE FUNCTION insert_audit_anchor(p_org UUID, p_seq BIGINT, p_hash BYTEA, p_at TIMESTAMPTZ, p_key TEXT, p_sig BYTEA)
RETURNS VOID
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    INSERT INTO audit_anchors (org_id, seq, hash, at, key_id, signature) VALUES (p_org, p_seq, p_hash, p_at, p_key, p_sig)
$$;
REVOKE ALL ON FUNCTION insert_audit_anchor(UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION insert_audit_anchor(UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, BYTEA) TO guardspec_app;
