-- Gives the application role its old name back, as migrations 004 to 009
-- expect it. The grants follow the role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guardspec_app')
       AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ps_app') THEN
        ALTER ROLE guardspec_app RENAME TO ps_app;
    END IF;
END
$$;
