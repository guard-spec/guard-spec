-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- SAML providers, their identities and logins go; SCIM data goes.
ALTER TABLE org_security DROP COLUMN scim_revoke_keys;
DROP INDEX idx_api_keys_created_by;
ALTER TABLE api_keys DROP COLUMN created_by;
DROP FUNCTION user_other_orgs(UUID, UUID);
DROP FUNCTION lookup_scim_token(TEXT);
DROP TABLE org_group_roles;
DROP TABLE scim_group_members;
DROP TABLE scim_groups;
DROP TABLE scim_users;
DROP TABLE scim_tokens;
DROP TABLE saml_assertions;
DROP TABLE saml_requests;
DELETE FROM sessions WHERE method LIKE 'saml:%';
DELETE FROM identity_providers WHERE type = 'saml';
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_fields;
ALTER TABLE identity_providers
    DROP COLUMN saml_groups_attribute,
    DROP COLUMN saml_name_attribute,
    DROP COLUMN saml_email_attribute,
    DROP COLUMN saml_allow_idp_initiated,
    DROP COLUMN saml_metadata,
    ALTER COLUMN client_secret_env SET NOT NULL,
    ALTER COLUMN client_id SET NOT NULL;
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_type;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_type CHECK (type IN ('google', 'oidc'));
