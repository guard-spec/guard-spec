-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- API key policy (RF-5f318378): allowed addresses, rotation and an
-- organization-wide maximum lifetime.
--
-- allowed_cidrs: the networks (CIDRs or single addresses) a key may be used
-- from; empty, the default, allows every address. The gateway checks the
-- client address it resolved through TRUSTED_PROXIES.
--
-- A rotation creates a successor key and gives the old one an expiry at the
-- end of the overlap window; rotated_to names the successor (its prefix),
-- rotated_at when. api_keys.expires_at was always enforced by lookup_api_key.
--
-- org_security.api_key_max_lifetime_days: every new key of the org expires
-- within this many days (NULL: no limit); the control plane refuses a later
-- expiry and fills in the latest one when a key is created without.

ALTER TABLE api_keys
    ADD COLUMN allowed_cidrs TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN rotated_to    TEXT,
    ADD COLUMN rotated_at    TIMESTAMPTZ;

ALTER TABLE org_security
    ADD COLUMN api_key_max_lifetime_days INT
        CONSTRAINT org_security_api_key_max_lifetime CHECK (api_key_max_lifetime_days IS NULL OR api_key_max_lifetime_days BETWEEN 1 AND 3650);

-- The gateway's lookup (004) also returns the allowed addresses. Same rules:
-- active keys only, with the owner's rights, nothing else exposed. Gateways
-- from before this migration read only the first two columns and keep working.
DROP FUNCTION lookup_api_key(TEXT);
CREATE FUNCTION lookup_api_key(hash TEXT)
RETURNS TABLE (org_id UUID, project_id UUID, allowed_cidrs TEXT[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT k.org_id, k.project_id, k.allowed_cidrs FROM api_keys k
    WHERE k.key_hash = hash
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > NOW())
$$;
REVOKE ALL ON FUNCTION lookup_api_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_key(TEXT) TO guardspec_app;
