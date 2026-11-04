ALTER TABLE upstreams
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS retries,
    DROP COLUMN IF EXISTS max_tokens_cap,
    DROP COLUMN IF EXISTS api_version,
    DROP COLUMN IF EXISTS headers,
    DROP COLUMN IF EXISTS models,
    DROP COLUMN IF EXISTS display_name,
    DROP COLUMN IF EXISTS provider;
