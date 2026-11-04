-- The organizations a user belongs to, for GET /v1/organizations (the admin
-- UI's organization list). org_memberships and organizations are row-level
-- secured by app.org_id, and this list spans organizations, so it runs with
-- the owner's rights, like lookup_api_key (004). It returns only the given
-- user's memberships; the control plane passes the user id of the verified
-- token.
CREATE FUNCTION user_organizations(uid UUID)
RETURNS TABLE (id UUID, name TEXT, slug TEXT, role TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT o.id, o.name, o.slug, m.role::text
    FROM org_memberships m
    JOIN organizations o ON o.id = m.org_id
    WHERE m.user_id = uid
$$;
REVOKE ALL ON FUNCTION user_organizations(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION user_organizations(UUID) TO guardspec_app;
