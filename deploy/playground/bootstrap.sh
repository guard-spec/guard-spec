#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Prepares the playground's database after the migrations (docker-compose.yml
# in this directory runs it on every `up`; it is idempotent):
#
# 1. sets the guardspec_app password (../postgres/set-app-password.sh, which
#    also refuses weak passwords);
# 2. creates the "playground" org and its one API key from
#    PLAYGROUND_GATEWAY_KEY: only the key's SHA-256 is stored, as the control
#    plane would; other keys of the org are revoked, so changing the variable
#    rotates the key;
# 3. makes the requests table (the audit log) drop every row, so that not
#    even a hash or a length of a visitor's prompt is kept.
#
# Needs superuser credentials in the libpq environment (PGHOST, PGUSER,
# PGDATABASE, PGPASSWORD).
set -eu

sh /set-app-password.sh

key="${PLAYGROUND_GATEWAY_KEY:-}"
case "$key" in
gs_*) ;;
*)
	echo "PLAYGROUND_GATEWAY_KEY must start with gs_ (generate one: echo gs_\$(openssl rand -hex 24))" >&2
	exit 1
	;;
esac
if [ "${#key}" -lt 35 ]; then
	echo "PLAYGROUND_GATEWAY_KEY is too short: use gs_ and at least 32 random characters" >&2
	exit 1
fi
hash=$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)
prefix=$(printf '%s' "$key" | cut -c1-11)
rpm="${GATEWAY_RATE_LIMIT_RPM:-1200}"

# Values go in as psql variables, quoted by psql, never spliced into SQL.
psql -v ON_ERROR_STOP=1 -q -v key_hash="$hash" -v key_prefix="$prefix" -v rpm="$rpm" <<'SQL'
BEGIN;
INSERT INTO organizations (name, slug) VALUES ('Playground', 'playground')
ON CONFLICT (slug) DO NOTHING;

UPDATE api_keys SET revoked_at = NOW()
WHERE org_id = (SELECT id FROM organizations WHERE slug = 'playground')
  AND key_hash <> :'key_hash' AND revoked_at IS NULL;

INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, rpm_limit)
SELECT :'key_hash', :'key_prefix', 'playground proxy', id, (:'rpm')::int
FROM organizations WHERE slug = 'playground'
ON CONFLICT (key_hash) DO UPDATE SET rpm_limit = EXCLUDED.rpm_limit, revoked_at = NULL;

-- The audit log keeps hashes and lengths of every request even with content
-- storage off; the playground keeps nothing.
CREATE OR REPLACE FUNCTION playground_drop_row() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
DROP TRIGGER IF EXISTS playground_drop_requests ON requests;
CREATE TRIGGER playground_drop_requests BEFORE INSERT ON requests
FOR EACH ROW EXECUTE FUNCTION playground_drop_row();
DELETE FROM requests;
COMMIT;
SQL
echo "playground org, key ${prefix}... and audit drop trigger ready"
