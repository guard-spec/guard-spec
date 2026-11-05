-- Per-organization exemplars for the L3 similarity layer (RF-e61791e8).
-- "block" texts count as attacks, "allow" texts as benign, next to the
-- built-in exemplar set. The gateway caches each org's embeddings and reloads
-- them when organizations.exemplars_version changes; the trigger below bumps
-- it on every insert, update and delete.
ALTER TABLE organizations ADD COLUMN exemplars_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE org_exemplars (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    label       TEXT NOT NULL CONSTRAINT org_exemplars_label CHECK (label IN ('block', 'allow')),
    text        TEXT NOT NULL CONSTRAINT org_exemplars_text CHECK (char_length(text) BETWEEN 1 AND 4000),
    source      TEXT NOT NULL DEFAULT 'manual' CONSTRAINT org_exemplars_source CHECK (char_length(source) <= 200),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX org_exemplars_org ON org_exemplars (org_id, created_at, id);

ALTER TABLE org_exemplars ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_exemplars ON org_exemplars
    USING (org_id = current_setting('app.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_exemplars TO guardspec_app;

-- Runs as the caller, so RLS on organizations still applies: the change and
-- the bump happen in the same org scope (app.org_id).
CREATE FUNCTION bump_exemplars_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        UPDATE organizations SET exemplars_version = exemplars_version + 1 WHERE id = OLD.org_id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') AND (TG_OP = 'INSERT' OR NEW.org_id <> OLD.org_id) THEN
        UPDATE organizations SET exemplars_version = exemplars_version + 1 WHERE id = NEW.org_id;
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER org_exemplars_version
    AFTER INSERT OR UPDATE OR DELETE ON org_exemplars
    FOR EACH ROW EXECUTE FUNCTION bump_exemplars_version();
