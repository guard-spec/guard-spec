<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment guides

> Tiếng Việt: [README.vi.md](README.vi.md).

Reference guides for running Guard Spec outside a laptop.

> **Status: reference templates, not yet verified by the maintainers.**
> Community-tested: not yet. If you deploy this, please open an
> [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a pull
> request with what worked and what did not. See
> [CONTRIBUTING.md](../../CONTRIBUTING.md).

| Guide | Covers | Status |
|---|---|---|
| [aws.md](aws.md) | EKS with the Helm chart, or ECS on Fargate; RDS for PostgreSQL 17, Secrets Manager, ALB + ACM, CloudWatch | Template, not tested on AWS |
| [gcp.md](gcp.md) | GKE Autopilot with the Helm chart, or Cloud Run; Cloud SQL for PostgreSQL 17, Secret Manager, HTTPS load balancer, Cloud Logging | Template, not tested on GCP |
| [on-premise.md](on-premise.md) | One VM with Docker Compose, vanilla Kubernetes and OpenShift, air-gapped installs, a reverse proxy for TLS | Template; the compose path is the one the README documents |

What the maintainers did check while writing these guides, on a local Docker
host with the 0.1.0 images: the migrations apply to PostgreSQL 17 with
`migrate/migrate:v4.20.1`, `deploy/postgres/set-app-password.sh` sets the
application role password, and `guard-spec-gateway-full:0.1.0` and
`guard-spec-control-plane:0.1.0` start with an arbitrary non-root UID (group
0) and a read-only root filesystem, with `/readyz` reporting
`"layers":["l1","l2","l3"]`. Nothing cloud-specific was run.

## Read first

These guides do not repeat the README. They assume you know:

- [Quick start](../../README.md#quick-start) and
  [Production](../../README.md#production): the secrets and how the services
  refuse weak ones.
- [Install from a release](../../README.md#install-from-a-release): the
  images and archives.
- [Models](../../README.md#models) and [docs/models.md](../models.md):
  `models pull`, pinning, rollback, air-gapped installs.
- [Configuration](../../README.md#configuration): every environment
  variable.
- [Operations](../../README.md#operations), in particular
  [Kubernetes](../../README.md#kubernetes) and
  [Identity, SSO and two-factor authentication](../../README.md#identity-sso-and-two-factor-authentication).
- [Security model and limitations](../../README.md#security-model-and-limitations).

## What every deployment needs

| Piece | Notes |
|---|---|
| PostgreSQL | 17 is what compose and CI use. Two roles: an owner role that runs the migrations (`ps` in compose) and `guardspec_app`, which migration 004 creates without a password. Roles are cluster-wide, so 004 fails on a server where `guardspec_app` already exists (another database or installation): give each installation a server of its own |
| Migrations | `migrations/` of the release tag, applied with `migrate` as the owner role, before the services start. The services never run them; the Helm chart does when `migrations.enabled=true` (a pre-install / pre-upgrade hook), otherwise you do |
| App password | `GUARDSPEC_APP_PASSWORD` applied to `guardspec_app` after every migration run: `deploy/postgres/set-app-password.sh` or the chart's `dbRoles` job |
| Gateway | `ghcr.io/guard-spec/guard-spec-gateway:0.4.0` (models mounted at `/models`) or `-gateway-full:0.4.0` (models inside). Port 8080 for clients, 9090 for metrics |
| Control plane | `ghcr.io/guard-spec/guard-spec-control-plane:0.4.0`. Port 8081 for the API and the admin UI at `/ui/`, 9091 for metrics |
| Secrets | `GUARDSPEC_APP_PASSWORD` (both services, as `PGPASSWORD`), `JWT_SECRET`, `MFA_ENC_KEY` and `ADMIN_PASSWORD` (control plane), the owner password (migrations only), `UPSTREAM_LLM_KEY` / `UPSTREAM_KEY_*` (gateway) |
| TLS | The services speak plain HTTP. Terminate TLS in a load balancer or reverse proxy in front of them |

## Things that hold everywhere

- **`MFA_ENC_KEY` must be backed up with the database.** It encrypts every
  user's TOTP secret. Restoring a database without the key that matches it
  locks out everyone who has 2FA, and the control plane refuses to start
  without it once users have 2FA.
- **Keep the control plane private.** Only the gateway's port 8080 needs to
  reach your applications. The control plane (API and admin UI) and both
  metrics ports belong on an internal network, a VPN or behind an
  identity-aware proxy.
- **`/readyz` answers 503 only for a missing required layer.** With
  `DETECTOR_REQUIRE_ML=true` (set in `gateway-full`) a missing model layer
  stops the gateway at start (or, under `GUARD_ENV=dev`, makes `/readyz`
  answer 503). Without it, a gateway without its models runs L1 only and
  reports ready with `"degraded":true`. Check `detector.layers` and
  `detector.degraded` in a smoke test.
- **Rate limits are per gateway replica** and in memory. Put a rate limiter
  or WAF in front for abuse protection.
- **Streaming.** `UPSTREAM_LLM_TIMEOUT` defaults to `5m` of silence. Load
  balancer idle or response timeouts shorter than your longest model answer
  cut streams; raise them.
- **Schema changes before 1.0.** Read the [CHANGELOG](../../CHANGELOG.md)
  and snapshot the database before every upgrade.

## The Helm chart on `main`

Chart 0.4.0 (see Unreleased in the [CHANGELOG](../../CHANGELOG.md)) adds,
each off by default: a **migration hook** (`migrations.enabled`), a **model
pull init container** (`models.pull`, into the claim or a per-pod
`emptyDir`, so several replicas no longer need a ReadWriteMany volume),
**Ingress** and OpenShift **Routes**, **HPA**, **PodDisruptionBudget**,
**topologySpreadConstraints**, **NetworkPolicies** and a **ServiceAccount**
with annotations for IRSA and Workload Identity. Reference values per
platform are in
[`deploy/helm/guard-spec/examples/`](../../deploy/helm/guard-spec/examples/)
(EKS, AKS, GKE, OpenShift): rendered and schema-checked in CI, installed on
kind by the `kind-e2e` job with its own values, not verified on the clouds.
Where a guide below shows plain manifests for one of these, the chart's
values now do the same job.

Mirrored registries and disconnected clusters: [../airgapped.md](../airgapped.md)
(images with cosign signatures and attestations, models, offline
verification, chart values, External Secrets). After installing,
`kubectl exec deploy/<release>-guard-spec-gateway -c gateway -- ./doctor`
(images from 0.2.0) checks the database, migrations, models,
layers, upstream and security settings.

Since chart 0.1.1 (see the [CHANGELOG](../../CHANGELOG.md)): `/models` is
mounted only with a models claim (or `models.pull`), so
`guard-spec-gateway-full` works with
`models.persistence.enabled=false`; the gateway defaults to a 2Gi memory
limit; the `dbRoles` job takes its securityContext from values and leaves the
UID to OpenShift; and `MFA_ENC_KEY` can sit in `existingSecret`.

**Patching the chart output.** Helm 4 accepts only post-renderer plugins for
`--post-renderer`; a plain script, as Helm 3 allowed, is rejected
(`plugin ... not found`). To add kustomize patches, wrap the script in a
post-renderer plugin, or render and apply without a Helm release: write
`helm template` output into a kustomization's resources, then
`kubectl kustomize <dir> | kubectl apply -f -`. Hooks such as `dbRoles` then
run as ordinary Jobs, not before the services.

## Contributing

If you run Guard Spec on one of these platforms, a short report helps more
than a polished guide: platform and versions, what you changed from the
guide, and what failed. Open an
[issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a pull
request against `docs/deploy/` (see [CONTRIBUTING.md](../../CONTRIBUTING.md);
commits need a DCO sign-off). Security problems go through
[SECURITY.md](../../SECURITY.md), never a public issue.
