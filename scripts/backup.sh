#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Backs up a Guard Spec compose stack: the database (pg_dump, custom format),
# the .env that holds its secrets and encryption keys, and Caddy's
# certificates when the stack has Caddy (deploy/compose/production). Restore
# with scripts/restore.sh. The stack keeps running; pg_dump reads a
# consistent snapshot.
#
# Usage:
#
#   scripts/backup.sh [-f compose file] [-p project] [-e env file] [-o dir]
#
#   -f  compose file (default: docker-compose.yml at the repository root;
#       production: deploy/compose/production/docker-compose.yml)
#   -p  compose project name (default: the file's own name: or the directory)
#   -e  env file (default: .env next to the compose file)
#   -o  output directory, created (default: backups/guardspec-<UTC time>
#       at the repository root)
#
# The output directory (mode 700) holds:
#
#   guardspec.dump   pg_dump -Fc of the database
#   guardspec.env    the env file: database passwords, JWT_SECRET and
#                    MFA_ENC_KEY (the key that encrypts 2FA secrets in the
#                    database; without it every user's 2FA is lost), and the
#                    upstream, SSO and alert secrets the database refers to
#                    by variable name only
#   caddy-data.tgz   Caddy's /data: certificates, ACME account, internal CA
#   MANIFEST         time, images, migration version, row counts, sha256
#
# It holds secrets: store it encrypted and off the host. Models are not
# included; models-init pulls them again (docs/upgrade.md).
#
# shellcheck disable=SC2016 # $POSTGRES_DB and $1 in single quotes expand in the container
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
file=$root/docker-compose.yml
project=
envfile=
out=

die() {
	echo "backup: $*" >&2
	exit 1
}

while getopts f:p:e:o:h opt; do
	case $opt in
	f) file=$OPTARG ;;
	p) project=$OPTARG ;;
	e) envfile=$OPTARG ;;
	o) out=$OPTARG ;;
	*)
		sed -n '4,/^set -eu/p' "$0" | grep -v '^# shellcheck\|^set -eu' | sed 's/^# \{0,1\}//'
		exit 2
		;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || die "unexpected argument: $1 (see -h)"

command -v docker >/dev/null 2>&1 || die "docker is not installed"
[ -f "$file" ] || die "compose file not found: $file"
[ -n "$envfile" ] || envfile=$(dirname "$file")/.env
[ -f "$envfile" ] || die "env file not found: $envfile (it holds the secrets a restore needs)"
[ -n "$out" ] || out=$root/backups/guardspec-$(date -u +%Y%m%dT%H%M%SZ)
[ ! -e "$out" ] || die "$out exists; choose another -o"

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

dc exec -T postgres pg_isready -U ps -q ||
	die "the postgres service is not running in this project (start the stack, or check -f / -p)"

umask 077
mkdir -p "$out"

echo "backup: dumping the database to $out/guardspec.dump"
dc exec -T postgres sh -c 'pg_dump -U ps -d "$POSTGRES_DB" -Fc' >"$out/guardspec.dump" ||
	die "pg_dump failed"
[ -s "$out/guardspec.dump" ] || die "pg_dump wrote nothing"

cp "$envfile" "$out/guardspec.env"

if dc ps --services --status running 2>/dev/null | grep -qx caddy; then
	echo "backup: saving Caddy's certificates and CA"
	dc exec -T caddy tar -C /data -czf - . >"$out/caddy-data.tgz" || die "could not read Caddy's /data"
fi

sha() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

{
	echo "created:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "compose:    $file"
	echo "project:    ${project:-(default)}"
	echo "database:   $(dc exec -T postgres sh -c 'echo "$POSTGRES_DB"')"
	echo "postgres:   $(psql_ps 'SHOW server_version')"
	echo "migration:  $(psql_ps 'SELECT version, dirty FROM schema_migrations') (version|dirty)"
	for t in organizations users api_keys policies upstreams requests; do
		printf 'rows.%s: %s\n' "$t" "$(psql_ps "SELECT count(*) FROM $t" 2>/dev/null || echo '?')"
	done
	dc ps --format '{{.Service}} {{.Image}}' 2>/dev/null | sort | sed 's/^/image:      /'
	for f in guardspec.dump guardspec.env caddy-data.tgz; do
		if [ -f "$out/$f" ]; then
			printf 'sha256:     %s  %s\n' "$(sha "$out/$f")" "$f"
		fi
	done
} >"$out/MANIFEST"

echo "backup: done: $out"
sed 's/^/  /' "$out/MANIFEST"
echo "backup: it contains secrets (guardspec.env): store it encrypted and off this host"
