-- Earlier versions of migration 004 gave ps_app a password that is public in
-- this repository. Clear it; the deployment sets the real one after migrating
-- (deploy/postgres/set-app-password.sh, run by the compose db-roles service).
ALTER ROLE ps_app PASSWORD NULL;
