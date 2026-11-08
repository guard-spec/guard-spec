-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- SIEM export (RF-f2f95010). Each sink sends an organization's events
-- (events table: detections, security, configuration and activity events;
-- metadata only) as OCSF records to Splunk HEC, Elasticsearch, Microsoft
-- Sentinel, syslog over TLS or an HTTP endpoint. The cursor is the last
-- event delivered, by (created_at, id); delivery is at least once.
CREATE TABLE siem_sinks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL CONSTRAINT siem_sinks_name CHECK (char_length(name) BETWEEN 1 AND 100),
    kind            TEXT NOT NULL CONSTRAINT siem_sinks_kind CHECK (kind IN ('splunk_hec', 'elastic', 'sentinel', 'syslog', 'http')),
    -- Non-secret settings: URLs, index, tenant and client ids, CA PEM.
    config          JSONB NOT NULL DEFAULT '{}' CONSTRAINT siem_sinks_config CHECK (pg_column_size(config) <= 16384),
    -- The variable holding the secret (ALERTS_SECRET_ORGS kind siem), never the secret.
    secret_env      TEXT CONSTRAINT siem_sinks_secret_env CHECK (secret_env ~ '^[A-Z][A-Z0-9_]{1,63}$'),
    -- Event types to send (exact, or a family such as "detection."); NULL: all.
    event_types     TEXT[],
    min_severity    alert_severity NOT NULL DEFAULT 'info',
    allow_private   BOOLEAN NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    cursor_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cursor_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    failures        INT NOT NULL DEFAULT 0,
    last_error      TEXT CONSTRAINT siem_sinks_last_error CHECK (char_length(last_error) <= 1000),
    last_success_at TIMESTAMPTZ,
    delivered       BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_siem_sinks_org ON siem_sinks (org_id, created_at);
CREATE INDEX idx_siem_sinks_due ON siem_sinks (next_attempt_at) WHERE enabled;
CREATE INDEX idx_events_org_created ON events (org_id, created_at, id);
ALTER TABLE siem_sinks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_siem_sinks ON siem_sinks
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON siem_sinks TO guardspec_app;

-- The export worker claims due sinks of every organization (RLS hides them
-- from guardspec_app otherwise) for lease: another control plane replica
-- skips a claimed sink until the lease ends or the worker reschedules it.
CREATE FUNCTION claim_siem_sinks(lease INTERVAL, max_sinks INT)
RETURNS TABLE (org_id UUID, id UUID)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    UPDATE siem_sinks s SET next_attempt_at = NOW() + lease
    WHERE s.id IN (
        SELECT x.id FROM siem_sinks x WHERE x.enabled AND x.next_attempt_at <= NOW()
        ORDER BY x.next_attempt_at LIMIT max_sinks FOR UPDATE SKIP LOCKED)
    RETURNING s.org_id, s.id
$$;
REVOKE ALL ON FUNCTION claim_siem_sinks(INTERVAL, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_siem_sinks(INTERVAL, INT) TO guardspec_app;
