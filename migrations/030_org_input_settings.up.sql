-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Per-organization input settings (RF-113cd269).
--
-- What the gateway accepts as input for one organization, within the
-- instance's limits (MAX_SCAN_TOKENS, PDF_EXTRACT, UNSCANNED_PARTS):
--
--   input_mode             text_only refuses every image, file and audio
--                          part; hybrid accepts text and the allowed files.
--   max_input_tokens       a request over it is refused before it is scanned;
--                          NULL: the instance's limit.
--   allowed_file_types     the file types hybrid accepts (today: pdf).
--   unreadable_file_action an allowed file the gateway cannot read: block
--                          refuses the request, pass forwards it unscanned.
--
-- An organization without a row inherits the instance's behaviour, exactly
-- as before this migration. The gateway reads the row with the org's guard
-- settings, in the org's row-level security scope.
--
-- Loosening the settings with two-person approval on waits for a second
-- admin: approval_requests kind 'input_settings.loosen', at most one pending
-- per organization (migration 029's index).

CREATE TABLE org_input_settings (
    org_id                 UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    input_mode             TEXT NOT NULL CONSTRAINT org_input_settings_mode
                               CHECK (input_mode IN ('text_only', 'hybrid')),
    max_input_tokens       INT CONSTRAINT org_input_settings_max_tokens
                               CHECK (max_input_tokens IS NULL OR max_input_tokens BETWEEN 1 AND 10000000),
    allowed_file_types     TEXT[] NOT NULL DEFAULT '{}' CONSTRAINT org_input_settings_types
                               CHECK (allowed_file_types <@ ARRAY['pdf']::text[]
                                      AND (input_mode = 'hybrid' OR cardinality(allowed_file_types) = 0)),
    unreadable_file_action TEXT NOT NULL DEFAULT 'block' CONSTRAINT org_input_settings_unreadable
                               CHECK (unreadable_file_action IN ('block', 'pass')),
    updated_by             UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE org_input_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_org_input_settings ON org_input_settings
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_input_settings TO guardspec_app;

ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_kind;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_kind
    CHECK (kind IN ('policy.disable', 'policy.delete', 'content_storage.enable', 'org.delete', 'input_settings.loosen'));
