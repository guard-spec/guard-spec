-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

DROP FUNCTION IF EXISTS claim_siem_sinks(INTERVAL, INT);
DROP INDEX IF EXISTS idx_events_org_created;
DROP TABLE IF EXISTS siem_sinks;
