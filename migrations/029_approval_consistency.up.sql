-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Consistent two-person approval (RF-5f318378).
--
-- A request can now end as 'cancelled': what it is about is gone or already
-- done (the policy was deleted or is already disabled), it repeats a request
-- that was already pending, or its kind no longer needs approval.
--
-- Deleting a policy no longer goes through approval: a policy can only be
-- deleted once it is disabled, and disabling is what waits for the second
-- admin. Pending 'policy.delete' requests are cancelled; the kind stays
-- valid so the decided ones keep their history.
--
-- At most one request per (organization, kind, target) is pending at a
-- time; asking again answers with the pending one. Duplicates left from
-- before are cancelled, keeping the oldest.
--
-- Instance administrators approve organization deletions, so they see the
-- pending 'org.delete' requests of every organization (instance scope).

ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_status;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_status
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled'));

UPDATE approval_requests SET status = 'expired'
WHERE status = 'pending' AND expires_at <= NOW();

UPDATE approval_requests
SET status = 'cancelled', decided_at = NOW(),
    decision_note = 'deleting a policy no longer needs approval: disable it (which does), then delete it'
WHERE status = 'pending' AND kind = 'policy.delete';

UPDATE approval_requests a
SET status = 'cancelled', decided_at = NOW(), decision_note = 'the same change was already pending'
WHERE a.status = 'pending' AND EXISTS (
    SELECT 1 FROM approval_requests b
    WHERE b.status = 'pending' AND b.org_id = a.org_id AND b.kind = a.kind
      AND b.target IS NOT DISTINCT FROM a.target
      AND (b.created_at, b.id) < (a.created_at, a.id));

CREATE UNIQUE INDEX approval_requests_one_pending
    ON approval_requests (org_id, kind, (COALESCE(target, '')))
    WHERE status = 'pending';

CREATE POLICY instance_org_delete_approval_requests ON approval_requests FOR SELECT
    USING (kind = 'org.delete' AND current_setting('app.instance_scope', true) = 'on');
