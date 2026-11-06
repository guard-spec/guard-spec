-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

DROP INDEX IF EXISTS idx_sessions_revoked;
DROP FUNCTION IF EXISTS purge_activity_rows(TIMESTAMPTZ, INT);
DROP INDEX IF EXISTS idx_activity_log_at;
