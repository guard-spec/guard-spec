-- Services connect as this role. It is not a superuser and does not own the
-- tables, so RLS applies. It has no password here: the deployment sets one from
-- its own configuration (see deploy/postgres/set-app-password.sh).
CREATE ROLE ps_app LOGIN;
GRANT USAGE ON SCHEMA public TO ps_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ps_app;

-- These tables had RLS enabled with no policy, which denied every row.
CREATE POLICY tenant_isolation_orgs ON organizations
    USING (id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_org_members ON org_memberships
    USING (org_id = current_setting('app.org_id')::uuid);
CREATE POLICY tenant_isolation_project_members ON project_memberships
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = project_id AND p.org_id = current_setting('app.org_id')::uuid
    ));

-- The org is unknown until the key is resolved, so this lookup runs with the
-- owner's rights. It returns active keys only and exposes nothing else.
CREATE FUNCTION lookup_api_key(hash TEXT)
RETURNS TABLE (org_id UUID, project_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT k.org_id, k.project_id FROM api_keys k
    WHERE k.key_hash = hash
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > NOW())
$$;
REVOKE ALL ON FUNCTION lookup_api_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_key(TEXT) TO ps_app;
