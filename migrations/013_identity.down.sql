DROP FUNCTION IF EXISTS domain_join_orgs(TEXT, UUID);
DROP FUNCTION IF EXISTS user_org_security(UUID);
DROP TABLE IF EXISTS activity_log;
DROP TABLE IF EXISTS org_security;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS user_mfa;
DROP TABLE IF EXISTS oidc_codes;
DROP TABLE IF EXISTS oidc_states;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS identity_providers;
DROP TABLE IF EXISTS sessions;
ALTER TABLE users
    DROP COLUMN IF EXISTS last_login_at,
    DROP COLUMN IF EXISTS disabled_at,
    DROP COLUMN IF EXISTS is_instance_admin;
