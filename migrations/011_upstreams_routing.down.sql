ALTER TABLE requests DROP COLUMN IF EXISTS route_target;
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_default_upstream;
ALTER TABLE projects DROP COLUMN IF EXISTS default_upstream_id;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_default_upstream;
ALTER TABLE organizations DROP COLUMN IF EXISTS default_upstream_id;
DROP TABLE IF EXISTS upstreams;
