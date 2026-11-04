DROP FUNCTION IF EXISTS delete_user_memberships(UUID);
DROP FUNCTION IF EXISTS sole_owner_orgs(UUID);
DROP TABLE IF EXISTS instance_state;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS trust_email_for_linking;
ALTER TABLE oidc_codes
    DROP COLUMN IF EXISTS email,
    DROP COLUMN IF EXISTS subject,
    DROP COLUMN IF EXISTS provider_id,
    DROP COLUMN IF EXISTS purpose;
ALTER TABLE oidc_states DROP COLUMN IF EXISTS browser_hash;
ALTER TABLE users
    DROP COLUMN IF EXISTS mfa_locked_until,
    DROP COLUMN IF EXISTS mfa_failures,
    DROP CONSTRAINT IF EXISTS users_email_normalized;
-- Lower-cased emails stay lower-cased.
