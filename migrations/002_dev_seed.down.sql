-- requests.org_id and requests.project_id reference organizations and
-- projects without ON DELETE CASCADE, so the default organization cannot be
-- deleted while it has audit rows. Delete them first; every other table that
-- references the organization cascades.
DELETE FROM requests WHERE org_id = '00000000-0000-0000-0000-000000000001'
    OR project_id IN (SELECT id FROM projects WHERE org_id = '00000000-0000-0000-0000-000000000001');
DELETE FROM organizations WHERE id = '00000000-0000-0000-0000-000000000001';
