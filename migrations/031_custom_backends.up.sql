-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Custom backends (RF-d6ba510e): an upstream of provider "custom" is an
-- organization's own JSON API, reached through the gateway's
-- /v1/backend/{upstream}/{path}. backend holds what the gateway forwards and
-- scans (internal/backend):
--
--   {"path_prefixes": ["/search"], "methods": ["POST"], "key_header": "",
--    "scan": {"request": ["$.query"], "response": ["$.answer"],
--             "all_strings": false, "raw_text": false}}
--
-- The control plane validates it on save and the gateway again when it reads
-- it. A custom backend is never a chat upstream: it cannot be a default
-- upstream or a route rule's target (checked by the control plane, and the
-- gateway fails such a route closed).
ALTER TABLE upstreams DROP CONSTRAINT upstreams_provider;
ALTER TABLE upstreams ADD CONSTRAINT upstreams_provider CHECK (provider IN
    ('openai', 'anthropic', 'azure_openai', 'gemini', 'ollama', 'vllm', 'openai_compatible', 'custom'));

ALTER TABLE upstreams
    ADD COLUMN backend JSONB
        CONSTRAINT upstreams_backend CHECK (backend IS NULL OR jsonb_typeof(backend) = 'object'),
    ADD CONSTRAINT upstreams_backend_custom CHECK ((provider = 'custom') = (backend IS NOT NULL));
