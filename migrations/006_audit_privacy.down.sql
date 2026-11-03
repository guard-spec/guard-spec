ALTER TABLE requests
    DROP COLUMN IF EXISTS response_content,
    DROP COLUMN IF EXISTS response_bytes,
    DROP COLUMN IF EXISTS response_sha256,
    DROP COLUMN IF EXISTS request_content,
    DROP COLUMN IF EXISTS request_bytes,
    DROP COLUMN IF EXISTS request_sha256;
ALTER TABLE organizations DROP COLUMN IF EXISTS audit_store_content;
