-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Policy versions and log-only policies (RF-5f318378).
--
-- Every save of a policy (API, admin UI, config as code, a rollback) keeps
-- the whole policy as it was after the save: its rules, name, description,
-- scope and flags, with the author, the time and an optional reason. A
-- rollback copies an earlier version into the policy and is itself a new
-- version. policies.version keeps counting as before; (policy_id, version)
-- names one row here.
--
-- A log-only policy is evaluated like any other, but what its allow, block
-- and route rules would have decided is only recorded in the request log
-- (tag policy:would_<action>=<rule id>); the request goes on to the next
-- policy. It is how a stricter policy is tried on live traffic.

ALTER TABLE policies ADD COLUMN log_only BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE policy_versions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id      UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version        INT NOT NULL,
    -- create, update, rollback or config (applied from the YAML file)
    kind           TEXT NOT NULL CONSTRAINT policy_versions_kind CHECK (kind IN ('create', 'update', 'rollback', 'config')),
    name           TEXT NOT NULL,
    description    TEXT,
    -- The scope at the time; no foreign key, so the history outlives a project.
    project_id     UUID,
    enabled        BOOLEAN NOT NULL,
    log_only       BOOLEAN NOT NULL,
    rules          JSONB NOT NULL,
    author_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    author_email   TEXT,
    reason         TEXT CONSTRAINT policy_versions_reason CHECK (char_length(reason) <= 500),
    -- A rollback: the version that was restored.
    rolled_back_to INT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT policy_versions_policy_version UNIQUE (policy_id, version)
);
CREATE INDEX idx_policy_versions_org ON policy_versions (org_id, policy_id, version DESC);

ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_policy_versions ON policy_versions
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_versions TO guardspec_app;

-- Every existing policy starts its history with its current state, so the
-- first edit after the upgrade can be rolled back.
INSERT INTO policy_versions (org_id, policy_id, version, kind, name, description, project_id, enabled, log_only, rules, created_at)
SELECT org_id, id, version, 'update', name, description, project_id, enabled, log_only, rules, updated_at
FROM policies;
