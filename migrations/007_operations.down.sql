DROP FUNCTION purge_audit_rows(TIMESTAMPTZ, INT);
DROP INDEX idx_requests_created;
DROP FUNCTION claim_invite(TEXT);
DROP TABLE invites;
ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_tpm_limit_check,
    DROP CONSTRAINT api_keys_rpm_limit_check;
