<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment guides

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
| PostgreSQL | 17 is what compose and CI use. Two roles: an owner role that runs the migrations (`ps` in compose) and `guardspec_app`, which migration 004 creates without a password |
| Migrations | `migrations/` of the release tag, applied with `migrate` as the owner role, before the services start. Nothing in the images or the Helm chart runs them for you |
| App password | `GUARDSPEC_APP_PASSWORD` applied to `guardspec_app` after every migration run: `deploy/postgres/set-app-password.sh` or the chart's `dbRoles` job |
| Gateway | `ghcr.io/guard-spec/guard-spec-gateway:0.1.0` (models mounted at `/models`) or `-gateway-full:0.1.0` (models inside). Port 8080 for clients, 9090 for metrics |
| Control plane | `ghcr.io/guard-spec/guard-spec-control-plane:0.1.0`. Port 8081 for the API and the admin UI at `/ui/`, 9091 for metrics |
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
- **`/readyz` answers 200 even when degraded.** A gateway without its models
  runs L1 only and still reports ready. Check `detector.layers` and
  `detector.degraded` in a smoke test, or use `gateway-full` (which sets
  `DETECTOR_REQUIRE_ML=true` and refuses to start without its models).
- **Rate limits are per gateway replica** and in memory. Put a rate limiter
  or WAF in front for abuse protection.
- **Streaming.** `UPSTREAM_LLM_TIMEOUT` defaults to `5m` of silence. Load
  balancer idle or response timeouts shorter than your longest model answer
  cut streams; raise them.
- **Schema changes before 1.0.** Read the [CHANGELOG](../../CHANGELOG.md)
  and snapshot the database before every upgrade.

## Known gaps in the Helm chart (0.1.0)

From the CHANGELOG: the chart has **no autoscaling, PodDisruptionBudget,
Ingress or migration job**, and the **models volume is ReadWriteOnce** by
default. The cloud and Kubernetes guides show workarounds with plain
manifests next to the chart. Pull requests that add these to the chart are
welcome.

Two more limits found while writing these guides:

- The gateway Deployment always mounts a volume at `/models` (the PVC, or an
  `emptyDir` with `models.persistence.enabled=false`). That hides the models
  baked into `guard-spec-gateway-full`, so with the chart as it is, use the
  plain gateway image and fill the PVC. [on-premise.md](on-premise.md#gateway-full-with-the-helm-chart)
  shows a kustomize patch that removes the mount, as a workaround.
- The `dbRoles` job sets `runAsUser: 70` in the template, not in values. On
  OpenShift's `restricted-v2` SCC, leave `dbRoles.enabled=false` and run
  `set-app-password.sh` yourself.

## Contributing

If you run Guard Spec on one of these platforms, a short report helps more
than a polished guide: platform and versions, what you changed from the
guide, and what failed. Open an
[issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a pull
request against `docs/deploy/` (see [CONTRIBUTING.md](../../CONTRIBUTING.md);
commits need a DCO sign-off). Security problems go through
[SECURITY.md](../../SECURITY.md), never a public issue.
