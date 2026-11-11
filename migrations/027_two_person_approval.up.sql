-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Two-person approval (RF-5f318378).
--
-- An organization can require that a change which weakens its protection
-- or its records is confirmed by a second administrator: disabling or
-- deleting a policy, turning on the storage of prompt and answer content,
-- and deleting the organization. With two_person_approval on, such a
-- request creates a pending row here instead of taking effect; another
-- admin (never the requester) approves or rejects it, and a request that
-- nobody decides within approval_expiry_hours expires. Off (the default),
-- nothing changes.

ALTER TABLE org_security
    ADD COLUMN two_person_approval   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN approval_expiry_hours INT NOT NULL DEFAULT 24
        CONSTRAINT org_security_approval_expiry CHECK (approval_expiry_hours BETWEEN 1 AND 720);

CREATE TABLE approval_requests (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL CONSTRAINT approval_requests_kind
                           CHECK (kind IN ('policy.disable', 'policy.delete', 'content_storage.enable', 'org.delete')),
    -- What the request is about: a policy id, or the organization id.
    target             TEXT CONSTRAINT approval_requests_target CHECK (char_length(target) <= 512),
    payload            JSONB NOT NULL DEFAULT '{}',
    reason             TEXT CONSTRAINT approval_requests_reason CHECK (char_length(reason) <= 500),
    status             TEXT NOT NULL DEFAULT 'pending' CONSTRAINT approval_requests_status
                           CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    requested_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_by_email TEXT,
    decided_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_by_email   TEXT,
    decided_at         TIMESTAMPTZ,
    decision_note      TEXT CONSTRAINT approval_requests_note CHECK (char_length(decision_note) <= 500),
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_approval_requests_org ON approval_requests (org_id, status, created_at DESC);

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_approval_requests ON approval_requests
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON approval_requests TO guardspec_app;
