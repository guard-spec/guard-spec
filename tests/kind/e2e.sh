#!/usr/bin/env bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Kubernetes e2e of the Helm chart on kind: builds the gateway and control
# plane images from this checkout, installs Postgres and a fake upstream in
# the cluster (manifests.yaml), installs the chart with values.yaml (the
# migrations and dbRoles hooks, network policies, PDB, service account),
# then checks that EN and VI prompt injections are blocked and a benign
# prompt passes (check.py), runs `doctor` in a gateway pod, and upgrades the
# release once (the hooks run again on an up-to-date database).
#
# Detection: L1 only (no models volume), to keep the run short.
#
# Needs docker, kind, kubectl, helm and python3. Run from the repository root:
#
#   tests/kind/e2e.sh
#
# Env: CLUSTER (kind cluster name, default guard-spec-e2e), KIND_NODE_IMAGE
# (default: the pinned kindest/node below), SKIP_BUILD=1 (use existing
# guard-spec-gateway:e2e and guard-spec-control-plane:e2e images), KEEP=1
# (keep the cluster afterwards), EXTRA_VALUES=<file> (more chart values on top
# of values.yaml; tests/kind/values-models.yaml pulls the L2/L3 models),
# ONNX_DEPS_CACHE=<dir> (CI: the gateway build takes the ONNX archives from
# there when their SHA-256 matches, see build/gateway.Dockerfile).
set -euo pipefail

CLUSTER=${CLUSTER:-guard-spec-e2e}
# kind v0.33.0's image for Kubernetes 1.37, pinned by digest (kind release notes).
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}
NS=guard-spec
RELEASE=gs
DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
CTX="kind-$CLUSTER"
k() { kubectl --context "$CTX" -n "$NS" "$@"; }

pids=()
cleanup() {
	status=$?
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	if [ "$status" -ne 0 ] && kubectl config get-contexts "$CTX" >/dev/null 2>&1; then
		echo "--- e2e failed; cluster state:" >&2
		k get pods,jobs,svc,networkpolicy -o wide >&2 || true
		k describe pods >&2 || true
		for pod in $(k get pods -o name 2>/dev/null); do
			echo "--- logs $pod" >&2
			k logs "$pod" --all-containers --tail=80 >&2 || true
		done
	fi
	if [ "${KEEP:-}" != 1 ]; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
	fi
	exit "$status"
}
trap cleanup EXIT

rand() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }

echo "--- kind cluster $CLUSTER ($KIND_NODE_IMAGE)"
kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --wait 180s

if [ "${SKIP_BUILD:-}" != 1 ]; then
	echo "--- building images"
	onnx_cache=()
	if [ -n "${ONNX_DEPS_CACHE:-}" ]; then
		onnx_cache=(--build-context "onnx-cache=$ONNX_DEPS_CACHE" --build-arg ONNX_DEPS_CACHE=/onnx-cache)
	fi
	docker build ${onnx_cache[@]+"${onnx_cache[@]}"} -f "$ROOT/build/gateway.Dockerfile" -t guard-spec-gateway:e2e "$ROOT"
	docker build -f "$ROOT/build/control-plane.Dockerfile" -t guard-spec-control-plane:e2e "$ROOT"
fi
kind load docker-image --name "$CLUSTER" guard-spec-gateway:e2e guard-spec-control-plane:e2e

echo "--- namespace, secrets, Postgres, fake upstream"
kubectl --context "$CTX" create namespace "$NS"
ADMIN_EMAIL=admin@e2e.example.com
ADMIN_PASSWORD=$(rand)
k create secret generic guard-spec-secrets \
	--from-literal=POSTGRES_PASSWORD="$(rand)" \
	--from-literal=GUARDSPEC_APP_PASSWORD="$(rand)" \
	--from-literal=JWT_SECRET="$(rand)$(rand)" \
	--from-literal=ADMIN_PASSWORD="$ADMIN_PASSWORD" \
	--from-literal=MFA_ENC_KEY="$(python3 -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
k apply -f "$DIR/manifests.yaml"
k rollout status deployment/postgres --timeout=180s
k rollout status deployment/fake-upstream --timeout=180s

echo "--- helm install"
helm --kube-context "$CTX" install "$RELEASE" "$ROOT/deploy/helm/guard-spec" -n "$NS" \
	-f "$DIR/values.yaml" ${EXTRA_VALUES:+-f "$EXTRA_VALUES"} --wait --timeout 10m
k get pods -o wide

echo "--- requests"
k port-forward "svc/$RELEASE-guard-spec-gateway" 18080:8080 >/dev/null &
pids+=($!)
k port-forward "svc/$RELEASE-guard-spec-control-plane" 18081:8081 >/dev/null &
pids+=($!)
for _ in $(seq 1 30); do
	curl -fsS http://127.0.0.1:18080/readyz >/dev/null 2>&1 &&
		curl -fsS http://127.0.0.1:18081/health >/dev/null 2>&1 && break
	sleep 1
done
curl -fsS http://127.0.0.1:18080/readyz && echo
ADMIN_EMAIL=$ADMIN_EMAIL ADMIN_PASSWORD=$ADMIN_PASSWORD \
	GATEWAY=http://127.0.0.1:18080 CONTROL=http://127.0.0.1:18081 \
	python3 "$DIR/check.py"

echo "--- doctor in a gateway pod"
# Exit 0: no check failed (L2/L3 missing and sslmode=disable are warnings).
k exec "deploy/$RELEASE-guard-spec-gateway" -c gateway -- ./doctor

for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
pids=()

echo "--- helm upgrade (hooks again, database up to date)"
helm --kube-context "$CTX" upgrade "$RELEASE" "$ROOT/deploy/helm/guard-spec" -n "$NS" \
	-f "$DIR/values.yaml" ${EXTRA_VALUES:+-f "$EXTRA_VALUES"} --wait --timeout 10m
k exec "deploy/$RELEASE-guard-spec-gateway" -c gateway -- ./doctor -skip upstream,security,layers,models

echo "--- e2e passed"
