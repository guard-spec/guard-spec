-- Model providers (RF-N15): upstreams get a provider preset, a display name,
-- an allowlist of models, extra non-secret headers and limits. The gateway
-- still speaks the OpenAI chat-completions format to every provider.
--
-- The model column keeps its name and is exposed as default_model ("model"
-- stays an alias in the API for one release).
ALTER TABLE upstreams
    ADD COLUMN provider       TEXT NOT NULL DEFAULT 'openai_compatible'
        CONSTRAINT upstreams_provider CHECK (provider IN
            ('openai', 'anthropic', 'azure_openai', 'gemini', 'ollama', 'vllm', 'openai_compatible')),
    ADD COLUMN display_name   TEXT NOT NULL DEFAULT ''
        CONSTRAINT upstreams_display_name CHECK (char_length(display_name) <= 100),
    -- Empty: any model passes. Otherwise a request naming another model is
    -- refused (400 model_not_allowed).
    ADD COLUMN models         TEXT[] NOT NULL DEFAULT '{}'
        CONSTRAINT upstreams_models CHECK (cardinality(models) <= 100),
    -- Non-secret extra headers, checked by the control plane; keys go in
    -- api_key_env.
    ADD COLUMN headers        JSONB NOT NULL DEFAULT '{}'
        CONSTRAINT upstreams_headers CHECK (jsonb_typeof(headers) = 'object'),
    ADD COLUMN api_version    TEXT NOT NULL DEFAULT ''
        CONSTRAINT upstreams_api_version CHECK (api_version ~ '^[A-Za-z0-9.-]{0,32}$'),
    ADD COLUMN max_tokens_cap INT
        CONSTRAINT upstreams_max_tokens_cap CHECK (max_tokens_cap IS NULL OR max_tokens_cap BETWEEN 1 AND 10000000),
    ADD COLUMN retries        INT NOT NULL DEFAULT 0
        CONSTRAINT upstreams_retries CHECK (retries BETWEEN 0 AND 3),
    ADD COLUMN tags           TEXT[] NOT NULL DEFAULT '{}'
        CONSTRAINT upstreams_tags CHECK (cardinality(tags) <= 20);
