-- The application role gets no password from the migrations; the deployment
-- sets the real one after migrating (deploy/postgres/set-app-password.sh, run
-- by the compose db-roles service).
ALTER ROLE guardspec_app PASSWORD NULL;
