-- Per-organization scan settings (indirect injection, RF-9512eccc): which
-- parts of a request the detector classifies and how tool results are marked
-- for the model. An empty object keeps the gateway's environment defaults
-- (SCAN_ROLES, SPOTLIGHT). Example:
--   {"scan_roles": {"system": true}, "spotlight": "delimit"}
ALTER TABLE organizations
    ADD COLUMN guard_settings JSONB NOT NULL DEFAULT '{}'::jsonb
    CONSTRAINT organizations_guard_settings_object CHECK (jsonb_typeof(guard_settings) = 'object');
