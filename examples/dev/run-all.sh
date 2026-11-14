#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Runs every example against the gateways of examples/dev/start.sh and checks
# the allowed and blocked paths: each example must exit 0 and print the lines
# below. Used by .github/workflows/examples.yml; works locally too:
#
#   examples/dev/start.sh && examples/dev/run-all.sh; examples/dev/stop.sh
#
# Needs uv, and Node.js 22 with npm. EXAMPLES_SKIP_TS=1 skips the TypeScript
# examples, EXAMPLES_SKIP_PY=1 the Python ones.
set -u

cd "$(dirname "$0")/../.." || exit 1
root=$(pwd)
if [ -z "${GUARDSPEC_API_KEY:-}" ]; then
	set -a
	# shellcheck source=/dev/null
	. "$root/examples/dev/.state/env"
	set +a
fi
: "${GUARDSPEC_REDACT_BASE_URL:?run examples/dev/start.sh first}"

failed=0
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# check NAME DIR PATTERN... -- COMMAND...: runs COMMAND in DIR and checks that
# it exits 0 and prints a line starting with each PATTERN (a fixed string).
check() {
	name=$1 dir=$2
	shift 2
	patterns=""
	while [ "$1" != "--" ]; do
		patterns="$patterns
$1"
		shift
	done
	shift
	echo "== $name"
	(cd "$root/$dir" && "$@") >"$out" 2>&1
	status=$?
	cat "$out"
	ok=1
	[ "$status" -eq 0 ] || { echo "FAIL: $name exited $status"; ok=0; }
	echo "$patterns" | while IFS= read -r p; do
		[ -n "$p" ] || continue
		grep -qF -- "$p" "$out" || { echo "FAIL: $name did not print: $p"; exit 1; }
	done || ok=0
	[ "$ok" -eq 1 ] || failed=1
}

if [ "${EXAMPLES_SKIP_PY:-}" != 1 ]; then
	for ex in openai-sdk langchain llamaindex; do
		check "python/$ex" "examples/python/$ex" "allowed: " "streamed: " "blocked: content_filter" -- \
			uv run --frozen -q main.py
	done
	check "python/rag (INDIRECT_ACTION=block)" examples/python/rag \
		"shipping  block" "allowed (clean index): " "blocked (INDIRECT_ACTION=block): content_filter" -- \
		uv run --frozen -q main.py --expect block
	check "python/rag (INDIRECT_ACTION=redact)" examples/python/rag \
		"shipping  block" "allowed (clean index): " "allowed: " "[removed by Guard Spec: prompt injection detected in tool output]" -- \
		env GUARDSPEC_BASE_URL="$GUARDSPEC_REDACT_BASE_URL" uv run --frozen -q main.py --expect redact
fi

if [ "${EXAMPLES_SKIP_TS:-}" != 1 ]; then
	for ex in openai-sdk vercel-ai-sdk; do
		echo "== typescript/$ex: npm ci, typecheck"
		(cd "$root/examples/typescript/$ex" && npm ci --no-audit --no-fund --ignore-scripts >/dev/null && npm run -s typecheck) ||
			{ echo "FAIL: typescript/$ex did not install or typecheck"; failed=1; continue; }
		check "typescript/$ex" "examples/typescript/$ex" \
			"allowed: " "streamed: " "blocked: content_filter" "blocked (streaming): content_filter" -- npm start -s
	done
fi

check "n8n workflow shape" examples/n8n "ok: " -- python3 validate.py

check "custom-backend" examples/custom-backend "allowed: " "forwarded unchanged: yes" "redacted: " \
	"blocked: content_filter" "not reached: " "refused path: 403 path_not_allowed" -- python3 demo.py

if [ "$failed" -ne 0 ]; then
	echo "examples: FAILED"
	exit 1
fi
echo "examples: all passed"
