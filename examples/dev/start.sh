#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Starts a throwaway Guard Spec for the examples, from this checkout:
#
#   - Postgres with the migrations applied (docker compose, project
#     gs-examples, development credentials; nothing else of the stack);
#   - a fake OpenAI-compatible model (examples/dev/fake_upstream.py);
#   - a sample organization API (examples/custom-backend/sample_backend.py),
#     registered as the custom backend "search" of the development org;
#   - the gateway built from source (go build ./cmd/gateway), twice: one
#     with INDIRECT_ACTION=block, one with INDIRECT_ACTION=redact, both with
#     the rule layer only (DETECTOR_LAYERS=l1, no model download) and
#     UPSTREAM_ALLOW_PRIVATE=true (the sample backend is on 127.0.0.1);
#   - a random throwaway API key inserted into the database.
#
# It writes the variables the examples read to examples/dev/.state/env
# (KEY=value lines, also fit for $GITHUB_ENV):
#
#   set -a; . examples/dev/.state/env; set +a
#
# Stop everything with examples/dev/stop.sh. Needs docker compose v2, Go and
# python3. Ports (environment): EXAMPLES_PG_PORT (55432), EXAMPLES_GATEWAY_PORT
# (18180, block), EXAMPLES_REDACT_PORT (18181, redact), EXAMPLES_UPSTREAM_PORT
# (18199), EXAMPLES_BACKEND_PORT (18198). UPSTREAM_LLM_URL set in the
# environment replaces the fake model.
#
# Development only: the database password is the well-known one of
# docker-compose.override.yml and GUARD_ENV=dev turns off the production checks.
set -eu

cd "$(dirname "$0")/../.."
root=$(pwd)
state="$root/examples/dev/.state"
mkdir -p "$state"

pg_port=${EXAMPLES_PG_PORT:-55432}
gw_port=${EXAMPLES_GATEWAY_PORT:-18180}
redact_port=${EXAMPLES_REDACT_PORT:-18181}
up_port=${EXAMPLES_UPSTREAM_PORT:-18199}
backend_port=${EXAMPLES_BACKEND_PORT:-18198}

compose() {
	POSTGRES_PORT=$pg_port docker compose -p gs-examples \
		-f docker-compose.yml -f docker-compose.override.yml "$@"
}

echo "examples: starting Postgres (compose project gs-examples, port $pg_port)"
compose up -d --wait postgres
compose run --rm --no-deps migrate >/dev/null 2>&1 || compose run --rm --no-deps migrate
compose run --rm --no-deps db-roles >/dev/null

# A random key for this run only: gs_ and 32 hex characters, stored hashed.
key="gs_$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
hash=$(printf '%s' "$key" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U ps -d guardspec -c \
	"INSERT INTO api_keys (key_hash, key_prefix, alias, org_id)
	 VALUES ('$hash', '$(printf '%s' "$key" | cut -c1-11)', 'examples', '00000000-0000-0000-0000-000000000001')" >/dev/null

# The custom backend "search" (migration 031): POST /search, the query and the
# filters scanned, the result snippets guarded.
compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U ps -d guardspec -c \
	"INSERT INTO upstreams (org_id, name, base_url, provider, backend)
	 VALUES ('00000000-0000-0000-0000-000000000001', 'search', 'http://127.0.0.1:$backend_port', 'custom',
	   '{\"path_prefixes\":[\"/search\"],\"methods\":[\"POST\"],
	     \"scan\":{\"request\":[\"\$.query\",\"\$.filters[*]\"],\"response\":[\"\$.results[*].snippet\"],
	       \"all_strings\":false,\"raw_text\":false}}')
	 ON CONFLICT (org_id, name) DO NOTHING" >/dev/null

echo "examples: starting the sample backend on port $backend_port"
python3 examples/custom-backend/sample_backend.py --port "$backend_port" >"$state/backend.log" 2>&1 &
echo $! >"$state/backend.pid"

upstream=${UPSTREAM_LLM_URL:-}
if [ -z "$upstream" ]; then
	echo "examples: starting the fake model on port $up_port"
	python3 examples/dev/fake_upstream.py --port "$up_port" >"$state/upstream.log" 2>&1 &
	echo $! >"$state/upstream.pid"
	upstream="http://127.0.0.1:$up_port/v1"
fi

echo "examples: building the gateway"
go build -o "$state/gateway" ./cmd/gateway

start_gateway() { # port action
	GUARD_ENV=dev \
		LISTEN_ADDR=":$1" \
		METRICS_ADDR="127.0.0.1:$(($1 + 1000))" \
		DATABASE_URL="postgres://guardspec_app:guardspec_app@127.0.0.1:$pg_port/guardspec?sslmode=disable" \
		DETECTOR_LAYERS=l1 \
		UPSTREAM_LLM_URL="$upstream" \
		UPSTREAM_ALLOW_PRIVATE=true \
		INDIRECT_ACTION="$2" \
		"$state/gateway" >"$state/gateway-$2.log" 2>&1 &
	echo $! >"$state/gateway-$2.pid"
}
start_gateway "$gw_port" block
start_gateway "$redact_port" redact

for port in "$gw_port" "$redact_port"; do
	i=0
	until curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; do
		i=$((i + 1))
		if [ "$i" -ge 60 ]; then
			echo "examples: the gateway on port $port did not start; log:" >&2
			cat "$state"/gateway-*.log >&2
			exit 1
		fi
		sleep 1
	done
done

umask 077
cat >"$state/env" <<EOF
GUARDSPEC_BASE_URL=http://127.0.0.1:$gw_port
GUARDSPEC_API_KEY=$key
GUARDSPEC_REDACT_BASE_URL=http://127.0.0.1:$redact_port
GUARDSPEC_BACKEND_URL=http://127.0.0.1:$backend_port
MODEL=${MODEL:-fake-model}
EOF
echo "examples: ready. Gateway (INDIRECT_ACTION=block) http://127.0.0.1:$gw_port," \
	"(INDIRECT_ACTION=redact) http://127.0.0.1:$redact_port"
echo "examples: set -a; . examples/dev/.state/env; set +a   # then run an example"
