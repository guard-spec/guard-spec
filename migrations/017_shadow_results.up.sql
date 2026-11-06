-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Shadow mode (RF-eac8dc74): when the gateway runs a candidate L2 classifier
-- next to the active one (SHADOW_L2_MODEL), each sampled request gets one row
-- here, written in the same transaction as its requests row. It holds the two
-- models' names, their scores and the decision each would make at the direct
-- threshold, never any prompt or response content. Rows go when their
-- request does (audit retention), through the foreign key.
--
-- status: ok (both scored every text), timeout (the candidate missed its
-- budget), error (the candidate failed), skipped (no free shadow slot).
-- Shadow scores and both decisions are NULL unless status is ok.

CREATE TABLE shadow_results (
    request_id      UUID PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id      UUID,
    status          TEXT NOT NULL CONSTRAINT shadow_results_status CHECK (status IN ('ok', 'timeout', 'error', 'skipped')),
    active_model    TEXT CONSTRAINT shadow_results_active_model CHECK (char_length(active_model) <= 200),
    shadow_model    TEXT CONSTRAINT shadow_results_shadow_model CHECK (char_length(shadow_model) <= 200),
    active_score    REAL,
    shadow_score    REAL,
    active_l2       REAL,
    shadow_l2       REAL,
    active_decision TEXT CONSTRAINT shadow_results_active_decision CHECK (active_decision IN ('allow', 'block')),
    shadow_decision TEXT CONSTRAINT shadow_results_shadow_decision CHECK (shadow_decision IN ('allow', 'block')),
    texts           INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT shadow_results_decisions CHECK ((status = 'ok') = (active_decision IS NOT NULL AND shadow_decision IS NOT NULL))
);
CREATE INDEX idx_shadow_results_org_time ON shadow_results (org_id, created_at DESC, request_id DESC);
-- The disagreement list of the admin UI.
CREATE INDEX idx_shadow_results_disagree ON shadow_results (org_id, created_at DESC, request_id DESC)
    WHERE active_decision IS DISTINCT FROM shadow_decision;

ALTER TABLE shadow_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_shadow_results ON shadow_results
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON shadow_results TO guardspec_app;
