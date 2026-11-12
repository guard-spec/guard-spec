-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Migration 027 knows no 'cancelled': such requests read as expired (they
-- changed nothing). Pending requests may repeat again.
DROP POLICY instance_org_delete_approval_requests ON approval_requests;
DROP INDEX approval_requests_one_pending;
UPDATE approval_requests SET status = 'expired' WHERE status = 'cancelled';
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_status;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_status
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired'));
