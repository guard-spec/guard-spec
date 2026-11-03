-- The project was renamed from PromptShield to Guard Spec. Rename the
-- application role ps_app (created by migration 004) to guardspec_app.
--
-- ALTER ROLE ... RENAME keeps the role's OID, so every grant (tables, the
-- SECURITY DEFINER functions of 004 and 007, org_exemplars of 009) and every
-- policy follows it. The RLS policies name no role (they apply to PUBLIC), so
-- none has to be recreated. A SCRAM password survives the rename; an MD5 one
-- is cleared by PostgreSQL, and the deployment sets it again after migrating
-- (deploy/postgres/set-app-password.sh, run by the compose db-roles service).
--
-- Guarded so that it also runs on a database where the role was already
-- renamed by hand, or never existed.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ps_app') THEN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guardspec_app') THEN
            RAISE EXCEPTION 'both roles ps_app and guardspec_app exist; drop one of them before migrating';
        END IF;
        ALTER ROLE ps_app RENAME TO guardspec_app;
    ELSIF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guardspec_app') THEN
        CREATE ROLE guardspec_app LOGIN;
    END IF;
END
$$;

-- Idempotent for a renamed role; complete for a role created above. These
-- repeat the grants of migrations 004, 007 and 009.
GRANT USAGE ON SCHEMA public TO guardspec_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guardspec_app;
GRANT EXECUTE ON FUNCTION lookup_api_key(TEXT) TO guardspec_app;
GRANT EXECUTE ON FUNCTION claim_invite(TEXT) TO guardspec_app;
GRANT EXECUTE ON FUNCTION purge_audit_rows(TIMESTAMPTZ, INT) TO guardspec_app;
