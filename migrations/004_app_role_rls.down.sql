DROP FUNCTION lookup_api_key(TEXT);
DROP POLICY tenant_isolation_project_members ON project_memberships;
DROP POLICY tenant_isolation_org_members ON org_memberships;
DROP POLICY tenant_isolation_orgs ON organizations;
DROP OWNED BY ps_app;
DROP ROLE ps_app;
