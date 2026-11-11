-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Address restrictions and rotation links go; a key that was limited to
-- addresses works from anywhere again, so revoke such keys first if that
-- matters. Expiries set by rotations or the maximum lifetime stay.
DROP FUNCTION lookup_api_key(TEXT);
CREATE FUNCTION lookup_api_key(hash TEXT)
RETURNS TABLE (org_id UUID, project_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT k.org_id, k.project_id FROM api_keys k
    WHERE k.key_hash = hash
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > NOW())
$$;
REVOKE ALL ON FUNCTION lookup_api_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_key(TEXT) TO guardspec_app;

ALTER TABLE org_security DROP COLUMN api_key_max_lifetime_days;
ALTER TABLE api_keys
    DROP COLUMN rotated_at,
    DROP COLUMN rotated_to,
    DROP COLUMN allowed_cidrs;
