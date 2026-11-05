-- Operations: per-key rate limits, user invites, audit retention.

-- Rate limits per API key. The columns exist since 001; this gives them their
-- meaning. NULL uses the gateway default (RATE_LIMIT_RPM / RATE_LIMIT_TPM),
-- 0 means unlimited, and anything else is the limit per minute.
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_rpm_limit_check CHECK (rpm_limit IS NULL OR rpm_limit >= 0),
    ADD CONSTRAINT api_keys_tpm_limit_check CHECK (tpm_limit IS NULL OR tpm_limit >= 0);

-- Invites. The token is returned once to the admin who created the invite and
-- stored here only as its SHA-256.
CREATE TABLE invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        org_role NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    invited_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invites_org ON invites (org_id, created_at DESC);

ALTER TABLE invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_invites ON invites
    USING (org_id = current_setting('app.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON invites TO guardspec_app;

-- The org is unknown until the token is resolved, so claiming runs with the
-- owner's rights, like lookup_api_key. It marks one pending, unexpired invite
-- accepted and returns it; called inside the accepting transaction, a failure
-- later in that transaction rolls the claim back.
CREATE FUNCTION claim_invite(hash TEXT)
RETURNS TABLE (invite_id UUID, org_id UUID, email TEXT, role org_role)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    UPDATE invites i SET accepted_at = NOW()
    WHERE i.token_hash = hash
      AND i.accepted_at IS NULL
      AND i.revoked_at IS NULL
      AND i.expires_at > NOW()
    RETURNING i.id, i.org_id, i.email, i.role
$$;
REVOKE ALL ON FUNCTION claim_invite(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_invite(TEXT) TO guardspec_app;

-- Audit retention. Rows of every org are deleted, which RLS does not let guardspec_app
-- do, so the batch delete runs with the owner's rights. It removes at most
-- batch rows older than cutoff and returns how many it removed.
CREATE INDEX idx_requests_created ON requests (created_at);

CREATE FUNCTION purge_audit_rows(cutoff TIMESTAMPTZ, batch INT)
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    IF batch IS NULL OR batch < 1 OR batch > 100000 THEN
        RAISE EXCEPTION 'batch must be between 1 and 100000';
    END IF;
    DELETE FROM requests WHERE id IN (
        SELECT id FROM requests WHERE created_at < cutoff
        ORDER BY created_at LIMIT batch
        FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION purge_audit_rows(TIMESTAMPTZ, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_audit_rows(TIMESTAMPTZ, INT) TO guardspec_app;
