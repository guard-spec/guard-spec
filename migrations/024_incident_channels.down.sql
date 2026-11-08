-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- PagerDuty and Opsgenie channels and their deliveries go with the kinds.
DELETE FROM notification_outbox WHERE channel_kind IN ('pagerduty', 'opsgenie');
DELETE FROM notification_channels WHERE kind IN ('pagerduty', 'opsgenie');
ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_kind;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_kind
    CHECK (channel_kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email'));
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_kind;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind
    CHECK (kind IN ('telegram', 'slack', 'teams', 'webhook', 'a2a', 'email'));
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_secret_env;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_secret_env CHECK (
    secret_env ~ '^(GUARDSPEC_ALERT_|TELEGRAM_BOT_TOKEN_|SLACK_|TEAMS_|WEBHOOK_SECRET_|A2A_)[A-Z0-9_]*$'
    AND secret_env ~ '^[A-Z][A-Z0-9_]{2,63}$');
