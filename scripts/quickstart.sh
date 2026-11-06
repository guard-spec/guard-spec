#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Starts Guard Spec on a clean machine with the released images and the full
# detector (L1 rules + L2 classifier + L3 embeddings), or, with
# DETECTOR_LAYERS=l1,l2, in light mode (no L3; less memory, docs/sizing.md):
#
#   1. creates .env from .env.example with strong random secrets (and
#      DETECTOR_LAYERS when it is set), unless .env already exists (it is
#      never overwritten);
#   2. runs `docker compose -f docker-compose.yml up -d` (the released images;
#      not the dev override), whose models-init service pulls and verifies the
#      models before the gateway starts;
#   3. waits for the gateway's /readyz and prints the active layers.
#
# Usage, from the repository root (or a release source archive):
#
#   scripts/quickstart.sh [docker compose options, such as -p myproject]
#
# Environment: DETECTOR_LAYERS (l1,l2 for light mode), GUARDSPEC_VERSION
# (image tag), GATEWAY_PORT and the other
# ports of .env.example, MODELS_MIRROR, COMPOSE_PROJECT_NAME and
# QUICKSTART_TIMEOUT (seconds to wait for /readyz, default 600). Values set in
# the environment win over .env, as in docker compose.
set -eu

cd "$(dirname "$0")/.."

die() {
	echo "quickstart: $*" >&2
	exit 1
}

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) is not available"
command -v curl >/dev/null 2>&1 || die "curl is not installed"
[ -f docker-compose.yml ] || die "run this from a Guard Spec checkout (docker-compose.yml not found)"

# rand_hex N: N random bytes as 2N hex characters.
rand_hex() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex "$1"
	else
		od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
		echo
	fi
}

# rand_b64 N: N random bytes in base64.
rand_b64() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -base64 "$1"
	else
		head -c "$1" /dev/urandom | base64 | tr -d '\n'
		echo
	fi
}

admin_password=""
if [ -f .env ]; then
	echo "quickstart: .env exists, keeping it (delete it to generate new secrets)"
else
	[ -f .env.example ] || die ".env.example not found"
	postgres_password=$(rand_hex 24)
	app_password=$(rand_hex 24)
	jwt_secret=$(rand_hex 32)
	mfa_key=$(rand_b64 32)
	admin_password=$(rand_hex 12)
	for v in "$postgres_password" "$app_password" "$jwt_secret" "$mfa_key" "$admin_password"; do
		[ "${#v}" -ge 24 ] || die "could not generate random secrets (need openssl or /dev/urandom)"
	done
	umask 077
	# Only empty assignments are filled in; GUARD_ENV stays empty (production checks on).
	awk -v pg="$postgres_password" -v app="$app_password" -v jwt="$jwt_secret" \
		-v mfa="$mfa_key" -v admin="$admin_password" -v layers="${DETECTOR_LAYERS:-}" '
		/^POSTGRES_PASSWORD=$/      { print "POSTGRES_PASSWORD=" pg; next }
		/^GUARDSPEC_APP_PASSWORD=$/ { print "GUARDSPEC_APP_PASSWORD=" app; next }
		/^JWT_SECRET=$/             { print "JWT_SECRET=" jwt; next }
		/^MFA_ENC_KEY=$/            { print "MFA_ENC_KEY=" mfa; next }
		/^ADMIN_PASSWORD=$/         { print "ADMIN_PASSWORD=" admin; next }
		/^DETECTOR_LAYERS=$/        { print "DETECTOR_LAYERS=" layers; next }
		{ print }
	' .env.example >.env.tmp
	for k in POSTGRES_PASSWORD GUARDSPEC_APP_PASSWORD JWT_SECRET MFA_ENC_KEY ADMIN_PASSWORD; do
		grep -q "^$k=..*" .env.tmp || {
			rm -f .env.tmp
			die ".env.example has no empty $k= line to fill in"
		}
	done
	mv .env.tmp .env
	umask 022
	echo "quickstart: wrote .env with new random secrets (mode 600; keep it, back up MFA_ENC_KEY)"
fi

# env_value KEY: the value from the environment, else from .env.
env_value() {
	eval "v=\${$1:-}"
	if [ -z "$v" ]; then
		v=$(sed -n "s/^$1=//p" .env | tail -n 1)
	fi
	printf '%s' "$v"
}

layers=$(env_value DETECTOR_LAYERS | tr -d ' ')
layers=${layers:-l1,l2,l3}
case ",$layers," in
*,l3,*) size="about 270 MB of models" ;;
*,l2,*) size="about 135 MB of models (light mode, no L3)" ;;
*) size="no models (L1 only)" ;;
esac
echo "quickstart: starting the stack with layers $layers (the first start downloads images and $size)"
docker compose "$@" -f docker-compose.yml up -d

port=$(env_value GATEWAY_PORT)
cp_port=$(env_value CONTROL_PLANE_PORT)
url="http://localhost:${port:-8080}/readyz"
timeout=${QUICKSTART_TIMEOUT:-600}
waited=0
printf 'quickstart: waiting for %s ' "$url"
until body=$(curl -fsS "$url" 2>/dev/null); do
	if [ "$waited" -ge "$timeout" ]; then
		echo
		docker compose "$@" -f docker-compose.yml ps -a >&2 || true
		die "the gateway was not ready after ${timeout}s; see: docker compose $* -f docker-compose.yml logs models-init gateway"
	fi
	printf '.'
	sleep 5
	waited=$((waited + 5))
done
echo
echo "quickstart: ready: $body"
# l1,l2 -> "layers":["l1","l2"], as /readyz reports the active layers.
want="\"layers\":[\"$(printf '%s' "$layers" | sed 's/,/","/g')\"]"
case "$body" in
*"$want"*) echo "quickstart: detection layers active: $layers" ;;
*) echo "quickstart: warning: not every requested layer ($layers) is active; see detector.problems above and docs/models.md" >&2 ;;
esac

echo
echo "Gateway:        http://localhost:${port:-8080}"
echo "Admin UI:       http://localhost:${cp_port:-18081}/ui/"
echo "Admin login:    $(env_value ADMIN_EMAIL)"
if [ -n "$admin_password" ]; then
	echo "Admin password: $admin_password   (shown once; change it after the first login)"
else
	echo "Admin password: ADMIN_PASSWORD in .env"
fi
