-- Development seed data (safe to apply in production — uses fixed UUIDs, does nothing if already exists)
INSERT INTO organizations (id, name, slug, tier)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default', 'pro')
ON CONFLICT (id) DO NOTHING;
