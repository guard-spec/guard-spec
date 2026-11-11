-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Every organization goes back to the instance's input behaviour. Requests
-- to loosen input settings have nothing left to change: they go, since
-- migration 029's check does not know their kind.
DELETE FROM approval_requests WHERE kind = 'input_settings.loosen';
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_kind;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_kind
    CHECK (kind IN ('policy.disable', 'policy.delete', 'content_storage.enable', 'org.delete'));
DROP TABLE org_input_settings;
