#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Stops what examples/dev/start.sh started and deletes its database volume.
set -u

cd "$(dirname "$0")/../.." || exit 1
state=examples/dev/.state

for pid in "$state"/*.pid; do
	[ -f "$pid" ] || continue
	kill "$(cat "$pid")" 2>/dev/null || true
	rm -f "$pid"
done
docker compose -p gs-examples -f docker-compose.yml -f docker-compose.override.yml down -v --remove-orphans
rm -rf "$state"
