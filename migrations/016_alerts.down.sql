-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

DROP FUNCTION IF EXISTS user_org_session_policy(UUID);
DROP FUNCTION IF EXISTS confirm_channel_email(TEXT);
DROP FUNCTION IF EXISTS redeem_channel_link_code(TEXT, TEXT);
DROP FUNCTION IF EXISTS redeem_telegram_link_code(TEXT, TEXT);
DROP FUNCTION IF EXISTS alert_work_orgs();
DROP VIEW IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS email_link_codes;
DROP TABLE IF EXISTS channel_email_addresses;
DROP TABLE IF EXISTS channel_link_codes;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notification_outbox;
DROP TABLE IF EXISTS user_notification_prefs;
DROP TABLE IF EXISTS telegram_link_codes;
DROP TABLE IF EXISTS user_channel_links;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS alert_rule_hits;
DROP TABLE IF EXISTS alert_rules;
DROP TABLE IF EXISTS notification_channels;
DROP TABLE IF EXISTS user_group_members;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS events;
DROP TYPE IF EXISTS alert_severity;
