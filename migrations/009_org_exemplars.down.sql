DROP TRIGGER IF EXISTS org_exemplars_version ON org_exemplars;
DROP FUNCTION IF EXISTS bump_exemplars_version();
DROP TABLE IF EXISTS org_exemplars;
ALTER TABLE organizations DROP COLUMN IF EXISTS exemplars_version;
