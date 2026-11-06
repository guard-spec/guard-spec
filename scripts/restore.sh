#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Restores a backup of scripts/backup.sh into a compose stack whose database
# is empty: a new host, a new compose project, or the same project after
# `docker compose down -v`. It never overwrites a database that has tables.
#
# Usage:
#
#   scripts/restore.sh [-f compose file] [-p project] [-e env file] BACKUP_DIR
#
#   -f, -p, -e  as in scripts/backup.sh. When the env file does not exist,
#               the backup's guardspec.env is copied there (mode 600); when
#               it exists, its MFA_ENC_KEY must match the backup's (set
#               RESTORE_ALLOW_KEY_CHANGE=1 to restore anyway: every user's
#               2FA then has to be reset).
#
# Steps: verify the dump's sha256 against MANIFEST; start postgres; refuse a
# non-empty database; create the cluster-wide role guardspec_app (pg_dump
# does not carry roles); pg_restore; restore Caddy's /data when the backup and
# the stack have it; then `docker compose up -d --wait`, whose migrate and
# db-roles jobs apply newer migrations, if any, and set the guardspec_app
# password from the env file.
#
# shellcheck disable=SC2016 # $POSTGRES_DB and $1 in single quotes expand in the container
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
file=$root/docker-compose.yml
project=
envfile=

die() {
	echo "restore: $*" >&2
	exit 1
}

while getopts f:p:e:h opt; do
	case $opt in
	f) file=$OPTARG ;;
	p) project=$OPTARG ;;
	e) envfile=$OPTARG ;;
	*)
		sed -n '4,/^set -eu/p' "$0" | grep -v '^# shellcheck\|^set -eu' | sed 's/^# \{0,1\}//'
		exit 2
		;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || die "usage: scripts/restore.sh [-f file] [-p project] [-e env file] BACKUP_DIR"
dir=$1

command -v docker >/dev/null 2>&1 || die "docker is not installed"
[ -f "$file" ] || die "compose file not found: $file"
[ -f "$dir/guardspec.dump" ] || die "$dir/guardspec.dump not found"
[ -f "$dir/guardspec.env" ] || die "$dir/guardspec.env not found"
[ -n "$envfile" ] || envfile=$(dirname "$file")/.env

sha() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
if [ -f "$dir/MANIFEST" ]; then
	want=$(sed -n 's/^sha256: *\([0-9a-f]*\)  guardspec.dump$/\1/p' "$dir/MANIFEST")
	[ -z "$want" ] || [ "$want" = "$(sha "$dir/guardspec.dump")" ] ||
		die "guardspec.dump does not match the sha256 in MANIFEST"
fi

# env_get KEY FILE: the last KEY= value in FILE.
env_get() { sed -n "s/^$1=//p" "$2" | tail -n 1; }

if [ -f "$envfile" ]; then
	if [ "$(env_get MFA_ENC_KEY "$envfile")" != "$(env_get MFA_ENC_KEY "$dir/guardspec.env")" ] &&
		[ "${RESTORE_ALLOW_KEY_CHANGE:-}" != 1 ]; then
		die "MFA_ENC_KEY in $envfile differs from the backup's: 2FA secrets in the database would not decrypt. Use the backup's guardspec.env, or set RESTORE_ALLOW_KEY_CHANGE=1"
	fi
	echo "restore: using the existing $envfile"
else
	(umask 077 && cp "$dir/guardspec.env" "$envfile")
	echo "restore: wrote $envfile from the backup (mode 600)"
fi

dc() {
	if [ -n "$project" ]; then
		docker compose -f "$file" -p "$project" --env-file "$envfile" "$@"
	else
		docker compose -f "$file" --env-file "$envfile" "$@"
	fi
}

# psql_ps SQL: runs SQL as the superuser inside the postgres container.
psql_ps() {
	dc exec -T postgres sh -c 'psql -U ps -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tAq -c "$1"' sh "$1"
}

echo "restore: starting postgres"
dc up -d --wait postgres

n=$(psql_ps "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
[ "$n" -eq 0 ] ||
	die "the database already has $n tables; restore into an empty one (a new project, or docker compose down -v first)"

psql_ps "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'guardspec_app') THEN
    CREATE ROLE guardspec_app LOGIN;
  END IF;
END \$\$"

echo "restore: pg_restore $dir/guardspec.dump"
dc exec -T postgres sh -c 'pg_restore -U ps -d "$POSTGRES_DB" --exit-on-error' <"$dir/guardspec.dump" ||
	die "pg_restore failed"

if [ -f "$dir/caddy-data.tgz" ] && dc config --services | grep -qx caddy; then
	echo "restore: restoring Caddy's certificates and CA"
	dc run --rm --no-deps -T --entrypoint tar caddy -C /data -xzf - <"$dir/caddy-data.tgz"
fi

echo "restore: starting the stack"
dc up -d --wait --wait-timeout "${RESTORE_TIMEOUT:-600}"
echo "restore: done; restored rows:"
for t in organizations users api_keys policies upstreams requests; do
	printf '  %s: %s\n' "$t" "$(psql_ps "SELECT count(*) FROM $t")"
done
