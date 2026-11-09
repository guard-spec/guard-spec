-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- SAML 2.0 SSO and SCIM 2.0 provisioning (RF-39437a0f).
--
-- SAML providers are identity providers of type saml: instance-wide, like
-- OIDC ones. issuer holds the IdP's entity id and saml_metadata the IdP
-- metadata the administrator pasted (signing certificates and the SSO URL
-- come from it); they have no client id or secret.
--
-- SCIM is per organization: an org's tokens (stored as SHA-256) let its
-- identity provider create, update, deactivate and delete the org's users
-- and groups. org_group_roles maps an IdP group (a SCIM group's display name
-- or external id, or a value of a SAML provider's groups attribute) to a role
-- in the organization.

ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_type;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_type CHECK (type IN ('google', 'oidc', 'saml'));
ALTER TABLE identity_providers
    ALTER COLUMN client_id DROP NOT NULL,
    ALTER COLUMN client_secret_env DROP NOT NULL,
    ADD COLUMN saml_metadata            TEXT CONSTRAINT identity_providers_saml_metadata CHECK (char_length(saml_metadata) <= 262144),
    ADD COLUMN saml_allow_idp_initiated BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN saml_email_attribute     TEXT CONSTRAINT identity_providers_saml_email_attr CHECK (char_length(saml_email_attribute) <= 256),
    ADD COLUMN saml_name_attribute      TEXT CONSTRAINT identity_providers_saml_name_attr CHECK (char_length(saml_name_attribute) <= 256),
    ADD COLUMN saml_groups_attribute    TEXT CONSTRAINT identity_providers_saml_groups_attr CHECK (char_length(saml_groups_attribute) <= 256),
    ADD CONSTRAINT identity_providers_kind_fields CHECK (
        (type = 'saml' AND saml_metadata IS NOT NULL)
        OR (type <> 'saml' AND client_id IS NOT NULL AND client_secret_env IS NOT NULL));

-- A SAML login in progress (SP-initiated): the AuthnRequest id, which the
-- response must answer (InResponseTo), bound to the browser that started it.
CREATE TABLE saml_requests (
    request_id   TEXT PRIMARY KEY CONSTRAINT saml_requests_id CHECK (char_length(request_id) BETWEEN 1 AND 128),
    provider_id  UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    redirect     TEXT NOT NULL DEFAULT '/ui/',
    browser_hash TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_saml_requests_expires ON saml_requests (expires_at);

-- Assertions already used, until they expire: a captured response cannot be
-- replayed while it is still valid.
CREATE TABLE saml_assertions (
    provider_id  UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    assertion_id TEXT NOT NULL CONSTRAINT saml_assertions_id CHECK (char_length(assertion_id) BETWEEN 1 AND 256),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (provider_id, assertion_id)
);
CREATE INDEX idx_saml_assertions_expires ON saml_assertions (expires_at);
GRANT SELECT, INSERT, DELETE ON saml_requests, saml_assertions TO guardspec_app;

-- An organization's SCIM bearer tokens, as SHA-256.
CREATE TABLE scim_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL CONSTRAINT scim_tokens_name CHECK (char_length(name) BETWEEN 1 AND 100),
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_scim_tokens_org ON scim_tokens (org_id, created_at);

-- The users an organization's SCIM client manages. active false: the user
-- was deactivated; their membership is removed and its role kept here for a
-- reactivation. created: SCIM created the account (rather than linking an
-- existing one). disabled_account: deactivation also disabled the account.
CREATE TABLE scim_users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id      TEXT CONSTRAINT scim_users_external_id CHECK (char_length(external_id) <= 256),
    user_name        TEXT NOT NULL CONSTRAINT scim_users_user_name CHECK (char_length(user_name) BETWEEN 1 AND 320),
    active           BOOLEAN NOT NULL DEFAULT true,
    suspended_role   org_role,
    created          BOOLEAN NOT NULL DEFAULT false,
    disabled_account BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scim_users_org_user UNIQUE (org_id, user_id)
);
CREATE UNIQUE INDEX idx_scim_users_org_name ON scim_users (org_id, lower(user_name));
CREATE INDEX idx_scim_users_org_external ON scim_users (org_id, external_id);

CREATE TABLE scim_groups (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL CONSTRAINT scim_groups_display_name CHECK (char_length(display_name) BETWEEN 1 AND 256),
    external_id  TEXT CONSTRAINT scim_groups_external_id CHECK (char_length(external_id) <= 256),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_scim_groups_org_name ON scim_groups (org_id, lower(display_name));

CREATE TABLE scim_group_members (
    group_id     UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    scim_user_id UUID NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, scim_user_id)
);
CREATE INDEX idx_scim_group_members_user ON scim_group_members (scim_user_id);

-- IdP group → role, case insensitive. provider_id NULL: group_key matches a
-- group of the org's SCIM directory (display name or external id). Set: it
-- matches a value of that SAML provider's groups attribute, and applies at
-- login to a user who is already a member. Owner is never granted through
-- a group.
CREATE TABLE org_group_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    group_key   TEXT NOT NULL CONSTRAINT org_group_roles_key CHECK (char_length(group_key) BETWEEN 1 AND 256),
    role        org_role NOT NULL CONSTRAINT org_group_roles_role CHECK (role IN ('viewer', 'member', 'admin')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_org_group_roles_key ON org_group_roles
    (org_id, COALESCE(provider_id, '00000000-0000-0000-0000-000000000000'), lower(group_key));

ALTER TABLE scim_tokens        ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups        ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_group_roles    ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_scim_tokens ON scim_tokens
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY tenant_isolation_scim_users ON scim_users
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY tenant_isolation_scim_groups ON scim_groups
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY tenant_isolation_scim_group_members ON scim_group_members
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY tenant_isolation_org_group_roles ON org_group_roles
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_tokens, scim_users, scim_groups, scim_group_members, org_group_roles
    TO guardspec_app;

-- A SCIM request names no organization before its token is resolved, so the
-- lookup runs with the owner's rights, like lookup_api_key. It returns the
-- token's id and org when the token is live and records its use.
CREATE FUNCTION lookup_scim_token(hash TEXT)
RETURNS TABLE (token_id UUID, org_id UUID)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    UPDATE scim_tokens t SET last_used_at = NOW()
    WHERE t.token_hash = hash AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > NOW())
    RETURNING t.id, t.org_id
$$;
REVOKE ALL ON FUNCTION lookup_scim_token(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_scim_token(TEXT) TO guardspec_app;

-- The number of organizations other than org a user belongs to: a SCIM
-- deactivation disables the account only when this org is its only one.
CREATE FUNCTION user_other_orgs(uid UUID, org UUID)
RETURNS INT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT count(*)::int FROM org_memberships WHERE user_id = uid AND org_id <> org
$$;
REVOKE ALL ON FUNCTION user_other_orgs(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION user_other_orgs(UUID, UUID) TO guardspec_app;

-- A deactivated SCIM user's API keys: the keys they created are revoked when
-- the org asks for it (scim_revoke_keys, default on). Keys created before
-- this migration have no creator and are not touched.
ALTER TABLE api_keys ADD COLUMN created_by UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_api_keys_created_by ON api_keys (org_id, created_by) WHERE created_by IS NOT NULL;
ALTER TABLE org_security ADD COLUMN scim_revoke_keys BOOLEAN NOT NULL DEFAULT true;
