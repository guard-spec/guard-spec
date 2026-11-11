-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- The history goes; a log-only policy becomes a live one, so disable any
-- you do not want enforced before migrating down.
DROP TABLE policy_versions;
ALTER TABLE policies DROP COLUMN log_only;
