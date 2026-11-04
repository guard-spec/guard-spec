-- Identity (RF-N15): sessions, two-factor authentication, SSO (OIDC and
-- Google), instance administrators, org security policies and the activity
-- log of admin actions.
--
-- No secret is stored in plain text: TOTP secrets are AES-GCM encrypted with
-- MFA_ENC_KEY by the control plane, recovery codes are bcrypt hashes, the
-- one-time OIDC state and code values are stored as SHA-256 hashes, and an
-- identity provider names the environment variable (OIDC_SECRET_*) that holds
-- its client secret.
--
-- Tables keyed by user (sessions, identities, 2FA) are not row-level secured,
-- like users: a login happens before an organization is known. The
-- org-scoped ones (org_security, activity_log) are, like every other org table.

ALTER TABLE users
    ADD COLUMN is_instance_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN disabled_at       TIMESTAMPTZ,
    ADD COLUMN last_login_at     TIMESTAMPTZ;

-- One instance administrator: the earliest owner of the default organization
-- (seeded by 002), which is the bootstrap admin (ADMIN_EMAIL) on an instance
-- set up by the control plane. Other owners are not promoted. The control
-- plane promotes ADMIN_EMAIL at startup if no instance administrator exists.
UPDATE users SET is_instance_admin = true
WHERE id = (SELECT user_id FROM org_memberships
            WHERE org_id = '00000000-0000-0000-0000-000000000001' AND role = 'owner'
            ORDER BY joined_at, user_id LIMIT 1);

-- One row per login. The JWT carries the id as "sid"; a revoked or expired
-- row ends the session before the token does.
CREATE TABLE sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- password, google or oidc:<provider id>
    method       TEXT NOT NULL CONSTRAINT sessions_method CHECK (char_length(method) BETWEEN 1 AND 80),
    -- true when a TOTP or recovery code was checked at login
    mfa          BOOLEAN NOT NULL DEFAULT false,
    user_agent   TEXT CONSTRAINT sessions_user_agent CHECK (char_length(user_agent) <= 512),
    ip           TEXT CONSTRAINT sessions_ip CHECK (char_length(ip) <= 64),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON sessions (user_id, created_at DESC);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- Instance-wide SSO providers. The client secret is read from the variable
-- client_secret_env names, never stored.
CREATE TABLE identity_providers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type              TEXT NOT NULL CONSTRAINT identity_providers_type CHECK (type IN ('google', 'oidc')),
    display_name      TEXT NOT NULL CONSTRAINT identity_providers_display_name CHECK (char_length(display_name) BETWEEN 1 AND 100),
    issuer            TEXT NOT NULL CONSTRAINT identity_providers_issuer CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    client_id         TEXT NOT NULL CONSTRAINT identity_providers_client_id CHECK (char_length(client_id) BETWEEN 1 AND 512),
    client_secret_env TEXT NOT NULL CONSTRAINT identity_providers_secret_env CHECK (client_secret_env ~ '^OIDC_SECRET_[A-Z0-9_]{1,64}$'),
    scopes            TEXT[] NOT NULL DEFAULT '{openid,email,profile}',
    allowed_domains   TEXT[] NOT NULL DEFAULT '{}',
    auto_provision    BOOLEAN NOT NULL DEFAULT false,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A user's SSO identities: (provider, subject) names one account.
CREATE TABLE user_identities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL CONSTRAINT user_identities_subject CHECK (char_length(subject) BETWEEN 1 AND 255),
    email       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_identities_provider_subject UNIQUE (provider_id, subject),
    CONSTRAINT user_identities_user_provider UNIQUE (user_id, provider_id)
);

-- An SSO login in progress: the state (as its SHA-256), the nonce and the
-- PKCE verifier, for 10 minutes. link_user_id is set when a logged-in user
-- links the identity from their profile.
CREATE TABLE oidc_states (
    state_hash    TEXT PRIMARY KEY,
    provider_id   UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    redirect      TEXT NOT NULL DEFAULT '/ui/',
    link_user_id  UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_oidc_states_expires ON oidc_states (expires_at);

-- The one-time code the callback hands the UI (60 s), exchanged for the same
-- answer as a password login. Tokens never travel in URLs.
CREATE TABLE oidc_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method     TEXT NOT NULL,
    redirect   TEXT NOT NULL DEFAULT '/ui/',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);
CREATE INDEX idx_oidc_codes_expires ON oidc_codes (expires_at);

-- TOTP (RFC 6238). Secrets are AES-GCM ciphertexts (MFA_ENC_KEY, the user id
-- as additional data). pending_secret_enc is a setup not yet confirmed;
-- last_used_step refuses a code a second time within its window.
CREATE TABLE user_mfa (
    user_id            UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret_enc    BYTEA,
    pending_secret_enc BYTEA,
    enabled_at         TIMESTAMPTZ,
    last_used_step     BIGINT,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_recovery_codes_user ON mfa_recovery_codes (user_id);

-- The second step of a login (the mfa_token, a 5-minute JWT whose jti is the
-- id): purpose verify asks for a code, enroll for a 2FA setup. Each allows 5
-- attempts and one success.
CREATE TABLE mfa_challenges (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL CONSTRAINT mfa_challenges_purpose CHECK (purpose IN ('verify', 'enroll')),
    method     TEXT NOT NULL,
    attempts   INT NOT NULL DEFAULT 0,
    used_at    TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_challenges_expires ON mfa_challenges (expires_at);

-- Per-organization login rules. No row: the defaults (no 2FA requirement,
-- every login method, 12-hour sessions). allowed_login_methods NULL allows all.
CREATE TABLE org_security (
    org_id                 UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    require_mfa            BOOLEAN NOT NULL DEFAULT false,
    sso_satisfies_mfa      BOOLEAN NOT NULL DEFAULT false,
    allowed_login_methods  TEXT[],
    domain_join            JSONB NOT NULL DEFAULT '[]',
    session_lifetime_hours INT NOT NULL DEFAULT 12
        CONSTRAINT org_security_session_lifetime CHECK (session_lifetime_hours BETWEEN 1 AND 12),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE org_security ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_org_security ON org_security
    USING (org_id = current_setting('app.org_id')::uuid);

-- Admin actions. org_id NULL is an instance-level row (SSO providers, instance
-- users, logins), visible only in a transaction that sets app.instance_scope,
-- which the control plane does for instance administrators.
CREATE TABLE activity_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email TEXT,
    action      TEXT NOT NULL CONSTRAINT activity_log_action CHECK (char_length(action) BETWEEN 1 AND 80),
    target      TEXT CONSTRAINT activity_log_target CHECK (char_length(target) <= 512),
    ip          TEXT CONSTRAINT activity_log_ip CHECK (char_length(ip) <= 64),
    details     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_activity_log_org ON activity_log (org_id, at DESC, id DESC);
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_activity ON activity_log
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY instance_activity ON activity_log
    USING (org_id IS NULL AND current_setting('app.instance_scope', true) = 'on');

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, identity_providers, user_identities, oidc_states, oidc_codes,
    user_mfa, mfa_recovery_codes, mfa_challenges, org_security, activity_log TO guardspec_app;

-- The login rules of every organization a user belongs to, read at login
-- before any organization is chosen. Runs with the owner's rights, like
-- user_organizations (012); returns only the given user's organizations.
CREATE FUNCTION user_org_security(uid UUID)
RETURNS TABLE (org_id UUID, require_mfa BOOLEAN, sso_satisfies_mfa BOOLEAN)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT m.org_id, COALESCE(s.require_mfa, false), COALESCE(s.sso_satisfies_mfa, false)
    FROM org_memberships m
    LEFT JOIN org_security s ON s.org_id = m.org_id
    WHERE m.user_id = uid
$$;
REVOKE ALL ON FUNCTION user_org_security(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION user_org_security(UUID) TO guardspec_app;

-- The organizations whose domain_join rule matches an SSO login (verified
-- email domain and provider), with the role to grant.
CREATE FUNCTION domain_join_orgs(dom TEXT, provider UUID)
RETURNS TABLE (org_id UUID, role org_role)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT s.org_id, (r->>'role')::org_role
    FROM org_security s, jsonb_array_elements(s.domain_join) r
    WHERE lower(r->>'domain') = lower(dom)
      AND (r->>'provider_id')::uuid = provider
      AND r->>'role' IN ('viewer', 'member', 'admin')
$$;
REVOKE ALL ON FUNCTION domain_join_orgs(TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION domain_join_orgs(TEXT, UUID) TO guardspec_app;
