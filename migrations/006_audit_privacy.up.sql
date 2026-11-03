-- Audit privacy (decision D6). By default the gateway stores no prompt or
-- response content, only a SHA-256 and the length in bytes. Content is stored
-- when the organization opts in here, or when the gateway runs with
-- AUDIT_STORE_CONTENT=true.
ALTER TABLE organizations ADD COLUMN audit_store_content BOOL NOT NULL DEFAULT FALSE;

ALTER TABLE requests
    ADD COLUMN request_sha256   TEXT,   -- hex SHA-256 of the request body as received
    ADD COLUMN request_bytes    INT,
    ADD COLUMN request_content  TEXT,   -- NULL unless content storage is enabled
    ADD COLUMN response_sha256  TEXT,   -- hex SHA-256 of a buffered upstream response
    ADD COLUMN response_bytes   INT,
    ADD COLUMN response_content TEXT;   -- NULL unless content storage is enabled
