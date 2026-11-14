-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Custom backends go: the earlier schema has no provider for them. They
-- cannot be defaults or route targets, so nothing refers to them.
DELETE FROM upstreams WHERE provider = 'custom';
ALTER TABLE upstreams DROP CONSTRAINT upstreams_backend_custom;
ALTER TABLE upstreams DROP COLUMN backend;
ALTER TABLE upstreams DROP CONSTRAINT upstreams_provider;
ALTER TABLE upstreams ADD CONSTRAINT upstreams_provider CHECK (provider IN
    ('openai', 'anthropic', 'azure_openai', 'gemini', 'ollama', 'vllm', 'openai_compatible'));
