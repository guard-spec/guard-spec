-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Incident tools as alert channels (RF-656e36ac): PagerDuty (Events API v2)
-- and Opsgenie (Alert API). The secret is a variable (PAGERDUTY_*,
-- OPSGENIE_*) granted in ALERTS_SECRET_ORGS; config holds the region only.
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_kind;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind
    CHECK (kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email', 'pagerduty', 'opsgenie'));
ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_kind;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_kind
    CHECK (channel_kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email', 'pagerduty', 'opsgenie'));
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_secret_env;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_secret_env CHECK (
    secret_env ~ '^(GUARDSPEC_ALERT_|TELEGRAM_BOT_TOKEN_|SLACK_|TEAMS_|WEBHOOK_SECRET_|A2A_|PAGERDUTY_|OPSGENIE_)[A-Z0-9_]*$'
    AND secret_env ~ '^[A-Z][A-Z0-9_]{2,63}$');
