-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Pending requests go with the table; the guarded changes apply at once again.
DROP TABLE approval_requests;
ALTER TABLE org_security
    DROP COLUMN approval_expiry_hours,
    DROP COLUMN two_person_approval;
