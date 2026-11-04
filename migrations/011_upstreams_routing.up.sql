-- Named upstreams and routing (RF-863f958e). An organization defines the LLM
-- APIs its requests can go to; a rule with action "route" names one, and the
-- org and each project may name a default. The gateway resolves, in order:
-- the matching route rule's target, the project default, the org default,
-- UPSTREAM_LLM_URL, then the stub answer.
--
-- No secret is stored: api_key_env names an environment variable of the
-- gateway (UPSTREAM_KEY_*) that holds the key.
CREATE TABLE upstreams (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL CONSTRAINT upstreams_name CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    base_url     TEXT NOT NULL CONSTRAINT upstreams_base_url CHECK (char_length(base_url) BETWEEN 1 AND 2048),
    model        TEXT NOT NULL DEFAULT '' CONSTRAINT upstreams_model CHECK (char_length(model) <= 256),
    api_key_env  TEXT CONSTRAINT upstreams_api_key_env CHECK (api_key_env ~ '^UPSTREAM_KEY_[A-Z0-9_]{1,64}$'),
    timeout_ms   INT NOT NULL DEFAULT 300000 CONSTRAINT upstreams_timeout CHECK (timeout_ms BETWEEN 1000 AND 600000),
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT upstreams_org_name UNIQUE (org_id, name),
    -- Target of the composite foreign keys below.
    CONSTRAINT upstreams_org_id UNIQUE (org_id, id)
);

ALTER TABLE upstreams ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_upstreams ON upstreams
    USING (org_id = current_setting('app.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON upstreams TO guardspec_app;

-- Foreign keys are checked without RLS, so they include the org: a default can
-- only name an upstream of the same organization. NO ACTION (not RESTRICT)
-- lets an organization's deletion cascade through its upstreams.
ALTER TABLE organizations ADD COLUMN default_upstream_id UUID;
ALTER TABLE organizations ADD CONSTRAINT organizations_default_upstream
    FOREIGN KEY (id, default_upstream_id) REFERENCES upstreams (org_id, id);

ALTER TABLE projects ADD COLUMN default_upstream_id UUID;
ALTER TABLE projects ADD CONSTRAINT projects_default_upstream
    FOREIGN KEY (org_id, default_upstream_id) REFERENCES upstreams (org_id, id);

-- The upstream a request was sent to, or meant to go to when it failed
-- closed. NULL for UPSTREAM_LLM_URL, the stub, and refused requests.
ALTER TABLE requests ADD COLUMN route_target TEXT
    CONSTRAINT requests_route_target CHECK (char_length(route_target) <= 63);
