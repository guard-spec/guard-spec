CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for policy name search

-- Tenancy root tables

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    tier        TEXT NOT NULL DEFAULT 'free',   -- free|pro|enterprise
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT,
    hashed_password TEXT,         -- null for SSO-only accounts
    oidc_sub       TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TYPE org_role AS ENUM ('owner', 'admin', 'member', 'viewer');

CREATE TABLE org_memberships (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role       org_role NOT NULL DEFAULT 'member',
    invited_by UUID REFERENCES users(id),
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, org_id)
);

CREATE INDEX idx_org_memberships_org ON org_memberships (org_id, role);

CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, slug)
);

CREATE INDEX idx_projects_org ON projects (org_id);

CREATE TYPE project_role AS ENUM ('admin', 'member', 'viewer');

CREATE TABLE project_memberships (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role       project_role NOT NULL DEFAULT 'member',
    PRIMARY KEY (user_id, project_id)
);

-- API keys (hash is PK — plaintext never stored)

CREATE TABLE budgets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT,
    max_budget_usd  DECIMAL(12,6),
    soft_budget_usd DECIMAL(12,6),
    tpm_limit       BIGINT,
    rpm_limit       INT,
    budget_duration INTERVAL,
    budget_reset_at TIMESTAMPTZ,
    model_budgets   JSONB DEFAULT '{}'
);

CREATE INDEX idx_budgets_org ON budgets (org_id);

CREATE TABLE api_keys (
    key_hash          TEXT PRIMARY KEY,    -- SHA-256(plaintext)
    key_prefix        TEXT NOT NULL,       -- first 8 chars for display
    alias             TEXT,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id        UUID REFERENCES projects(id) ON DELETE CASCADE,
    budget_id         UUID REFERENCES budgets(id),
    tpm_limit         BIGINT,
    rpm_limit         INT,
    rpd_limit         INT,
    auto_rotate       BOOL NOT NULL DEFAULT FALSE,
    rotation_interval INTERVAL,
    last_rotation_at  TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_org ON api_keys (org_id);

-- Policies (CEL rules stored as JSON AST)

CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id  UUID REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    version     INT NOT NULL DEFAULT 1,
    enabled     BOOL NOT NULL DEFAULT TRUE,
    rules       JSONB NOT NULL DEFAULT '[]',   -- ordered rule array
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_org     ON policies (org_id, enabled);
CREATE INDEX idx_policies_project ON policies (project_id, enabled);
CREATE INDEX idx_policies_name    ON policies USING GIN (name gin_trgm_ops);

-- Requests / audit log (high-write — ClickHouse preferred; Postgres for < 1M requests/day)

CREATE TABLE requests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES organizations(id),
    project_id        UUID REFERENCES projects(id),
    api_key_hash      TEXT,
    model             TEXT,
    action            TEXT NOT NULL,   -- allow|block|redact|route
    rule_id           UUID,
    injection_score   REAL,
    toxicity_score    REAL,
    pii_entities      TEXT[],
    anomaly_score     REAL,
    had_tag_chars     BOOL,
    had_bidi          BOOL,
    input_tokens      INT,
    output_tokens     INT,
    latency_ms        INT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_requests_org  ON requests (org_id, created_at DESC);
CREATE INDEX idx_requests_proj ON requests (project_id, created_at DESC);

-- RLS (backstop — direct WHERE clauses still required for index use)

ALTER TABLE organizations    ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects         ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys         ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies         ENABLE ROW LEVEL SECURITY;
ALTER TABLE requests         ENABLE ROW LEVEL SECURITY;
ALTER TABLE budgets          ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_memberships  ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_memberships ENABLE ROW LEVEL SECURITY;

-- Direct equality comparison — NOT a subquery (subquery disables index)
CREATE POLICY tenant_isolation_projects  ON projects         USING (org_id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_keys      ON api_keys         USING (org_id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_policies  ON policies         USING (org_id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_requests  ON requests         USING (org_id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_budgets   ON budgets          USING (org_id = current_setting('app.org_id')::uuid);
