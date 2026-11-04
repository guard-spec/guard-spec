-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Real-time alerts and notifications (RF-35448968, docs/alerts.md).
--
-- Events from the gateway and the control plane land in events; the alert
-- worker of the control plane evaluates alert_rules over them, records alerts
-- and queues one notification_outbox row per delivery. Payloads hold metadata
-- only (ids, categories, scores), never prompt or response text. No secret is
-- stored: channels name the environment variable that holds theirs
-- (secret_env), and Telegram link codes are stored as SHA-256 hashes.
--
-- Org-scoped tables are row-level secured on app.org_id like every other org
-- table. Two tables are keyed by user, not org: user_channel_links and
-- telegram_link_codes. They are row-level secured too: a user sees their own
-- rows (app.user_id), and an org's transaction sees the links of that org's
-- members, which the worker needs to deliver. notifications (in-app) are
-- visible to their org and to their user, so the bell lists a user's
-- notifications across orgs.

CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');

-- ── Events ──────────────────────────────────────────────────────────────────

CREATE TABLE events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id   UUID,
    type         TEXT NOT NULL CONSTRAINT events_type CHECK (type ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$' AND char_length(type) <= 80),
    severity     alert_severity NOT NULL DEFAULT 'info',
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attrs        JSONB NOT NULL DEFAULT '{}' CONSTRAINT events_attrs_size CHECK (pg_column_size(attrs) <= 8192),
    -- Set by the alert worker once the rules have seen the event.
    processed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_events_unprocessed ON events (org_id, created_at) WHERE processed_at IS NULL;
CREATE INDEX idx_events_org_time ON events (org_id, occurred_at DESC);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_events ON events
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Groups ──────────────────────────────────────────────────────────────────

CREATE TABLE user_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CONSTRAINT user_groups_name CHECK (char_length(name) BETWEEN 1 AND 100),
    description TEXT NOT NULL DEFAULT '' CONSTRAINT user_groups_description CHECK (char_length(description) <= 500),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_groups_org_name UNIQUE (org_id, name),
    CONSTRAINT user_groups_org_id UNIQUE (org_id, id)
);
ALTER TABLE user_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_user_groups ON user_groups
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- Members must belong to the org: the foreign key to org_memberships removes
-- a member from every group of the org when they leave it.
CREATE TABLE user_group_members (
    org_id   UUID NOT NULL,
    group_id UUID NOT NULL,
    user_id  UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (org_id, group_id) REFERENCES user_groups (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, org_id) REFERENCES org_memberships (user_id, org_id) ON DELETE CASCADE
);
CREATE INDEX idx_user_group_members_user ON user_group_members (org_id, user_id);
ALTER TABLE user_group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_user_group_members ON user_group_members
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Channels ────────────────────────────────────────────────────────────────

CREATE TABLE notification_channels (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       TEXT NOT NULL CONSTRAINT notification_channels_name CHECK (char_length(name) BETWEEN 1 AND 100),
    kind       TEXT NOT NULL CONSTRAINT notification_channels_kind
        CHECK (kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email')),
    -- Non-secret settings only (docs/alerts.md).
    config     JSONB NOT NULL DEFAULT '{}' CONSTRAINT notification_channels_config_size CHECK (pg_column_size(config) <= 8192),
    -- The name of the variable that holds the secret, never the secret.
    secret_env TEXT CONSTRAINT notification_channels_secret_env CHECK (
        secret_env ~ '^(GUARDSPEC_ALERT_|TELEGRAM_BOT_TOKEN_|SLACK_|TEAMS_|WEBHOOK_SECRET_|A2A_)[A-Z0-9_]*$'
        AND secret_env ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT notification_channels_org_name UNIQUE (org_id, name)
);
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_notification_channels ON notification_channels
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Rules ───────────────────────────────────────────────────────────────────

CREATE TABLE alert_rules (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name             TEXT NOT NULL CONSTRAINT alert_rules_name CHECK (char_length(name) BETWEEN 1 AND 100),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    event_types      TEXT[] NOT NULL CONSTRAINT alert_rules_event_types CHECK (cardinality(event_types) BETWEEN 1 AND 20),
    -- Policy-text condition ("" always matches) and its compiled CEL.
    condition        TEXT NOT NULL DEFAULT '' CONSTRAINT alert_rules_condition CHECK (char_length(condition) <= 4000),
    condition_cel    TEXT NOT NULL DEFAULT '',
    threshold        INT NOT NULL DEFAULT 1 CONSTRAINT alert_rules_threshold CHECK (threshold BETWEEN 1 AND 100000),
    window_seconds   INT NOT NULL DEFAULT 300 CONSTRAINT alert_rules_window CHECK (window_seconds BETWEEN 60 AND 86400),
    severity         alert_severity NOT NULL DEFAULT 'warning',
    throttle_seconds INT NOT NULL DEFAULT 900 CONSTRAINT alert_rules_throttle CHECK (throttle_seconds BETWEEN 0 AND 604800),
    group_by         TEXT[] NOT NULL DEFAULT '{}' CONSTRAINT alert_rules_group_by
        CHECK (group_by <@ ARRAY['project_id', 'attrs.category', 'attrs.upstream_id']::text[]),
    quiet_hours      JSONB,
    auto_resolve     BOOLEAN NOT NULL DEFAULT false,
    recipients       JSONB NOT NULL DEFAULT '{"user_ids":[],"group_ids":[],"roles":[]}',
    channel_ids      UUID[] NOT NULL DEFAULT '{}' CONSTRAINT alert_rules_channel_ids CHECK (cardinality(channel_ids) <= 20),
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT alert_rules_org_name UNIQUE (org_id, name)
);
CREATE INDEX idx_alert_rules_org ON alert_rules (org_id) WHERE enabled;
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_alert_rules ON alert_rules
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- The events each rule matched, per dedupe key: the sliding window counts
-- these. Rows older than the longest window (one day) are pruned.
CREATE TABLE alert_rule_hits (
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id     UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    dedupe_key  TEXT NOT NULL,
    event_id    UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX idx_alert_rule_hits_window ON alert_rule_hits (rule_id, dedupe_key, occurred_at DESC);
CREATE INDEX idx_alert_rule_hits_org_time ON alert_rule_hits (org_id, occurred_at);
ALTER TABLE alert_rule_hits ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_alert_rule_hits ON alert_rule_hits
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Alerts ──────────────────────────────────────────────────────────────────

-- One row per firing episode of a rule and dedupe key. window_start is when
-- the episode began; at most one episode per (rule, key) is firing.
CREATE TABLE alerts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id          UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
    rule_name        TEXT NOT NULL,
    dedupe_key       TEXT NOT NULL,
    group_values     JSONB NOT NULL DEFAULT '{}',
    project_id       UUID,
    window_start     TIMESTAMPTZ NOT NULL,
    state            TEXT NOT NULL DEFAULT 'firing' CONSTRAINT alerts_state CHECK (state IN ('firing', 'resolved')),
    severity         alert_severity NOT NULL,
    first_at         TIMESTAMPTZ NOT NULL,
    last_at          TIMESTAMPTZ NOT NULL,
    count            INT NOT NULL DEFAULT 0,
    resolved_at      TIMESTAMPTZ,
    sample_event_ids UUID[] NOT NULL DEFAULT '{}' CONSTRAINT alerts_samples CHECK (cardinality(sample_event_ids) <= 10),
    last_notified_at TIMESTAMPTZ,
    notify_seq       INT NOT NULL DEFAULT 0,
    -- A quiet-hours suppression, for the history page.
    suppressed       BOOLEAN NOT NULL DEFAULT false,
    test             BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT alerts_dedupe UNIQUE (rule_id, dedupe_key, window_start)
);
CREATE UNIQUE INDEX alerts_one_firing ON alerts (rule_id, dedupe_key) WHERE state = 'firing';
CREATE INDEX idx_alerts_org_time ON alerts (org_id, last_at DESC, id DESC);
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_alerts ON alerts
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Personal links and preferences ──────────────────────────────────────────

CREATE TABLE user_channel_links (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CONSTRAINT user_channel_links_kind CHECK (kind IN ('telegram', 'slack', 'email')),
    -- Telegram chat id, Slack user id or email address; not a secret.
    address     TEXT NOT NULL CONSTRAINT user_channel_links_address CHECK (char_length(address) BETWEEN 1 AND 320),
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, kind)
);
ALTER TABLE user_channel_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_channel_links ON user_channel_links
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
-- An org's transaction reads its members' links (org_memberships is itself
-- scoped to app.org_id).
CREATE POLICY org_member_channel_links ON user_channel_links FOR SELECT
    USING (EXISTS (SELECT 1 FROM org_memberships m
                   WHERE m.user_id = user_channel_links.user_id
                     AND m.org_id = NULLIF(current_setting('app.org_id', true), '')::uuid));

-- /start codes of the Telegram bot: SHA-256 of the code, single use, 10 minutes.
CREATE TABLE telegram_link_codes (
    code_hash  TEXT PRIMARY KEY CONSTRAINT telegram_link_codes_hash CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_telegram_link_codes_user ON telegram_link_codes (user_id);
CREATE INDEX idx_telegram_link_codes_expires ON telegram_link_codes (expires_at);
ALTER TABLE telegram_link_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_telegram_link_codes ON telegram_link_codes
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

CREATE TABLE user_notification_prefs (
    user_id      UUID NOT NULL,
    org_id       UUID NOT NULL,
    channel_kind TEXT NOT NULL CONSTRAINT user_notification_prefs_kind CHECK (channel_kind IN ('telegram', 'slack', 'email')),
    enabled      BOOLEAN NOT NULL DEFAULT true,
    min_severity alert_severity NOT NULL DEFAULT 'info',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id, channel_kind),
    FOREIGN KEY (user_id, org_id) REFERENCES org_memberships (user_id, org_id) ON DELETE CASCADE
);
ALTER TABLE user_notification_prefs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_user_notification_prefs ON user_notification_prefs
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- ── Delivery ────────────────────────────────────────────────────────────────

CREATE TABLE notification_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alert_id        UUID REFERENCES alerts(id) ON DELETE CASCADE,
    rule_id         UUID,
    channel_kind    TEXT NOT NULL CONSTRAINT notification_outbox_kind
        CHECK (channel_kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email')),
    channel_id      UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    -- The resolved address (chat id, Slack user or channel, email, URL host);
    -- never a secret, never a URL path or query.
    target          TEXT NOT NULL DEFAULT '' CONSTRAINT notification_outbox_target CHECK (char_length(target) <= 320),
    payload         JSONB NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending'
        CONSTRAINT notification_outbox_state CHECK (state IN ('pending', 'sending', 'sent', 'failed', 'dead')),
    attempts        INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error      TEXT CONSTRAINT notification_outbox_last_error CHECK (char_length(last_error) <= 1000),
    last_status     INT,
    -- What the receiver returned to identify the delivery (an A2A task id).
    remote_id       TEXT CONSTRAINT notification_outbox_remote_id CHECK (char_length(remote_id) <= 200),
    idempotency_key TEXT NOT NULL CONSTRAINT notification_outbox_idempotency UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ
);
CREATE INDEX idx_notification_outbox_due ON notification_outbox (org_id, next_attempt_at)
    WHERE state IN ('pending', 'failed', 'sending');
CREATE INDEX idx_notification_outbox_org_time ON notification_outbox (org_id, created_at DESC, id DESC);
ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_notification_outbox ON notification_outbox
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

-- The delivery log the UI reads.
CREATE VIEW notification_deliveries WITH (security_invoker = true) AS
    SELECT o.id, o.org_id, o.alert_id, o.rule_id, a.rule_name, o.channel_kind, o.channel_id, c.name AS channel_name,
           o.user_id, o.target, o.state, o.attempts, o.next_attempt_at, o.last_error, o.last_status, o.remote_id,
           o.created_at, o.sent_at
    FROM notification_outbox o
    LEFT JOIN alerts a ON a.id = o.alert_id
    LEFT JOIN notification_channels c ON c.id = o.channel_id;

-- In-app notifications: visible to their org, and to their user across orgs.
CREATE TABLE notifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_id   UUID REFERENCES alerts(id) ON DELETE CASCADE,
    title      TEXT NOT NULL CONSTRAINT notifications_title CHECK (char_length(title) <= 300),
    body       TEXT NOT NULL CONSTRAINT notifications_body CHECK (char_length(body) <= 2000),
    severity   alert_severity NOT NULL,
    read_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notifications_user ON notifications (user_id, created_at DESC, id DESC);
CREATE INDEX idx_notifications_unread ON notifications (user_id) WHERE read_at IS NULL;
CREATE INDEX idx_notifications_org_time ON notifications (org_id, created_at);
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_notifications ON notifications
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY own_notifications ON notifications
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON events, user_groups, user_group_members, notification_channels, alert_rules,
    alert_rule_hits, alerts, user_channel_links, telegram_link_codes, user_notification_prefs, notification_outbox,
    notifications TO guardspec_app;
GRANT SELECT ON notification_deliveries TO guardspec_app;

-- The orgs the alert worker has work in: unprocessed events, deliveries due,
-- firing alerts (auto-resolve) and hits to prune. Runs with the owner's
-- rights so the worker can find them; returns org ids only.
CREATE FUNCTION alert_work_orgs()
RETURNS TABLE (org_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT DISTINCT e.org_id FROM events e WHERE e.processed_at IS NULL
    UNION
    SELECT DISTINCT o.org_id FROM notification_outbox o
        WHERE o.state IN ('pending', 'failed', 'sending') AND o.next_attempt_at <= NOW()
    UNION
    SELECT DISTINCT a.org_id FROM alerts a WHERE a.state = 'firing'
$$;
REVOKE ALL ON FUNCTION alert_work_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION alert_work_orgs() TO guardspec_app;

-- Redeems a Telegram /start code: the code must exist, be unused and not
-- expired. Marks it used and links chat to its user in one statement, so a
-- code works once. Returns the user, or NULL. The webhook knows no user or
-- org yet, hence the owner's rights; it can only act through a valid code.
CREATE FUNCTION redeem_telegram_link_code(hash TEXT, chat TEXT)
RETURNS UUID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    uid UUID;
BEGIN
    UPDATE telegram_link_codes SET used_at = NOW()
    WHERE code_hash = hash AND used_at IS NULL AND expires_at > NOW()
    RETURNING user_id INTO uid;
    IF uid IS NULL THEN
        RETURN NULL;
    END IF;
    INSERT INTO user_channel_links (user_id, kind, address, verified_at)
    VALUES (uid, 'telegram', chat, NOW())
    ON CONFLICT (user_id, kind) DO UPDATE SET address = EXCLUDED.address, verified_at = NOW();
    RETURN uid;
END
$$;
REVOKE ALL ON FUNCTION redeem_telegram_link_code(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION redeem_telegram_link_code(TEXT, TEXT) TO guardspec_app;
