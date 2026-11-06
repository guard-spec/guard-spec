-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Retried refusals (RF-ec4c8602): a client that gets a refusal may send the
-- same request again (Claude Code sends it six times). The gateway writes the
-- first refusal's row and counts identical refusals of the same API key that
-- follow within AUDIT_DEDUPE_WINDOW (default 10 s) here, instead of writing a
-- row for each. NULL: the row stands for one request; otherwise the number of
-- requests it stands for, the first included. Allowed requests are never
-- folded. The row's other columns are the first refusal's.
--
-- The column is on requests, so the table's row level security covers it.

ALTER TABLE requests ADD COLUMN repeat_count INT
    CONSTRAINT requests_repeat_count CHECK (repeat_count IS NULL OR repeat_count >= 2);
