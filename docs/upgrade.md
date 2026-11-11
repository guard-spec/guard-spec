<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Upgrade, rollback and backups

> Tiếng Việt: [upgrade.vi.md](upgrade.vi.md).

For the compose stacks: the quick start (`docker-compose.yml` at the
repository root) and the
[production compose](../deploy/compose/production/README.md). Kubernetes:
[docs/deploy/on-premise.md](deploy/on-premise.md#upgrade-and-rollback-1).

Three things have versions, and each rolls back on its own:

| What | Pinned by | Changes on upgrade | Rollback |
|---|---|---|---|
| Images (gateway, control plane) | `GUARDSPEC_VERSION` in `.env` | Code | Previous tag |
| Database schema | `migrations/` of the checkout; applied by the `migrate` job on every `up` | Only forward | Restore the pre-upgrade backup |
| Models | Each image's `models/manifest.yaml`, or `L2_MODEL` / `L3_MODEL` in `.env` | A release may recommend a newer model | `L2_MODEL=name@old-version` |

Before 1.0, a minor version can change the schema and the configuration:
read the [CHANGELOG](../CHANGELOG.md) for every version you skip.

## Backups

`scripts/backup.sh` saves what a restore needs, while the stack runs:

```bash
scripts/backup.sh                                                     # quick start
scripts/backup.sh -f deploy/compose/production/docker-compose.yml    # production
# backup: done: backups/guardspec-20261106T060839Z
```

| File | Contents | Why it matters |
|---|---|---|
| `guardspec.dump` | `pg_dump -Fc` of the database: organizations, users, API keys (hashes), policies, upstreams, alert rules, audit rows, `schema_migrations` | The data |
| `guardspec.env` | The `.env` the stack ran with | `POSTGRES_PASSWORD` and `GUARDSPEC_APP_PASSWORD`; `JWT_SECRET` (without it every session is invalid; users log in again); **`MFA_ENC_KEY`, the only key that encrypts data at rest** (TOTP 2FA secrets, AES-256-GCM): without it every user's 2FA must be reset; and the secrets the database names but does not hold: `UPSTREAM_KEY_*` / `UPSTREAM_LLM_KEY` (upstream `api_key_env`), `OIDC_SECRET_*` (SSO `client_secret_env`), alert channel secrets (`secret_env`), SMTP and bot tokens |
| `caddy-data.tgz` | Caddy's `/data` (production compose only) | Certificates, the ACME account, and with `CADDY_TLS=internal` the root CA your clients trust |
| `MANIFEST` | Time, images, migration version, row counts, SHA-256 of each file | What the backup is, and an integrity check for restore |

Not included, on purpose: models (pulled again and verified against the
manifest, or pinned with `L2_MODEL`), images (pulled by tag), and secrets
kept outside `.env` (a secret manager: back those up there).

The directory is created with mode 700 and holds every secret: encrypt it
(`age`, `gpg`, your backup tool's encryption) and keep it off the host.
API keys are stored as SHA-256 hashes, so the backup cannot reveal them;
password hashes are bcrypt.

Schedule it with cron or a systemd timer, for example daily:

```cron
15 3 * * * cd /opt/guard-spec && scripts/backup.sh -f deploy/compose/production/docker-compose.yml -o /var/backups/guardspec/$(date +\%F) && find /var/backups/guardspec -mindepth 1 -maxdepth 1 -mtime +14 -exec rm -rf {} +
```

### Restore

Into an empty database only (a new host, a new compose project, or after
`docker compose down -v`); a database with tables is refused:

```bash
scripts/restore.sh -f deploy/compose/production/docker-compose.yml backups/guardspec-20261106T060839Z
```

It checks the dump's SHA-256, writes the backup's `.env` when there is none
(and refuses a different `MFA_ENC_KEY` in an existing one), starts Postgres,
creates the cluster-wide role `guardspec_app` (a database dump does not carry
roles), runs `pg_restore`, puts Caddy's data back, then starts the stack:
`migrate` applies any migrations newer than the dump and `db-roles` sets the
`guardspec_app` password from `.env`. Logins, 2FA, API keys and the
internal CA keep working.

*Checked* on 2026-11-06 (arm64, Docker Desktop): a backup of a production
compose stack (1 organization, 1 user, 1 API key, 1 policy, 26,004 audit
rows) restored into a separate compose project. Checksums of the
organizations, users, API keys, policies and audit rows matched; the old
admin password and API key worked; an injection was blocked and a benign
prompt passed over HTTPS verified with the original Caddy root.

Managed databases: [docs/managed-postgres.md](managed-postgres.md#backups).

## Upgrading

```bash
scripts/backup.sh [-f ...]                          # 1. a backup to roll back to
git fetch --tags && git checkout v<new-version>     # 2. new migrations/ and compose files
# 3. .env: GUARDSPEC_VERSION=<new-version>; compare .env.example for new settings
docker compose [-f ...] pull                        # 4. images first, so the switch is short
docker compose [-f ...] up -d --wait                # 5. migrate and db-roles run before the services
curl -s localhost:8080/readyz | jq .detector        # 6. or https://<GATEWAY_HOST>/readyz
```

- Step 2 matters: the `migrate` job applies the `migrations/` directory of
  your checkout, so checkout and `GUARDSPEC_VERSION` must be the same
  release. A release source archive works the same as a checkout.
- During step 5 the gateway restarts; requests in flight fail and clients
  retry. One host cannot avoid that; for no downtime, run several gateway
  replicas behind a load balancer (Kubernetes, Helm chart).
- Models: if the new image recommends a new model version, `models-init`
  pulls it before the gateway starts (with `DETECTOR_REQUIRE_ML=true`, the
  production default, a failed pull stops `up` before the new gateway
  starts). With `L2_MODEL` / `L3_MODEL` pinned, the gateway
  keeps the pinned version.
- New classifier version: to try it before switching, keep `L2_MODEL`
  pinned and set `SHADOW_L2_MODEL=guardspec-classifier@<new>`. It scores the
  same traffic without deciding; compare in the admin UI (**Models**). Then
  switch without a restart with `POST /admin/models/reload` and
  `{"l2_model":"guardspec-classifier@<new>","shadow_l2_model":"off"}`
  (`GATEWAY_ADMIN_TOKEN`), and set `L2_MODEL` in `.env` for the next start
  (or set it and `up -d gateway`, which restarts). A reload checks the
  files' SHA-256 and keeps the running model if anything fails; see
  [README, Shadow mode and model reload](../README.md#shadow-mode-and-model-reload).
- Check after the upgrade: `/readyz` lists the layers you expect, the admin
  UI loads, a known injection is blocked
  ([README quick start](../README.md#quick-start)).
- With images from 0.2.0, also run `doctor` inside the gateway:
  `docker compose [-f ...] exec gateway /app/doctor`. It checks the database,
  that the migration version matches the image's `migrations/`, the model
  files against the manifest's SHA-256, which layers will load, the upstream
  and the security settings; exit code 1 means a check failed (`-strict`
  also fails on warnings, `-json` for scripts). See
  [README, Kubernetes](../README.md#kubernetes).

### Migration notes

What a release's migrations do beyond adding tables, and what to check
after them. The [CHANGELOG](../CHANGELOG.md) has the full upgrade notes of
every version.

- **026 (policy versions).** Adds `policies.log_only` and `policy_versions`,
  and writes one version row for every existing policy (its state at the
  upgrade), so the first edit after the upgrade can be rolled back. Down:
  the history is dropped and a log-only policy becomes live, so disable
  such policies first.
- **027 (two-person approval).** Adds `approval_requests` and two
  `org_security` columns; off for every organization. Down: pending
  requests are dropped.
- **028 (API key policy).** Replaces `lookup_api_key` so it also returns a
  key's allowed addresses. Gateways from before 0.6.0 keep working against
  the new function (they read the first two columns); a 0.6.0 gateway
  needs the migration, so apply it before the gateway starts, as the
  compose `migrate` job does. Set `TRUSTED_PROXIES` on the **gateway** when
  it runs behind a reverse proxy and you use `allowed_cidrs`: without it
  the proxy's address is the client. Down: keys limited to addresses work
  from anywhere again; revoke them first if that matters. Expiries set by
  rotations or the maximum lifetime stay.

## Rolling back

### Images, no schema change

When the release you leave added no migration (compare `migrations/` of the
two tags, or `MANIFEST`'s migration version with the new one):

```bash
git checkout v<old-version>
# .env: GUARDSPEC_VERSION=<old-version>
docker compose [-f ...] up -d --wait
```

### Images and schema

A newer schema with older code is not supported, and the `*.down.sql`
migrations drop what the newer version added, data included; they are not
the tested path. Restore the backup taken before the upgrade instead:

```bash
docker compose [-f ...] down -v      # removes the upgraded database: keep the backup safe first
git checkout v<old-version>
# .env: GUARDSPEC_VERSION=<old-version> (restore.sh keeps an existing .env)
scripts/restore.sh [-f ...] backups/guardspec-<before-upgrade>
```

Audit rows written between the backup and the rollback are lost. To keep
them, export them first (`GET /v1/organizations/{id}/requests`, or a
`pg_dump -t requests`).

`down -v` also removes the models volume of the production compose (pulled
again) and Caddy's data (restored from the backup).

### Models only

No image or schema change: pull the old version and pin it.

```bash
docker compose [-f ...] --profile models run --rm models-pull guardspec-classifier@<old>
# .env: L2_MODEL=guardspec-classifier@<old>
docker compose [-f ...] up -d gateway
curl -s localhost:8080/readyz | jq .detector.l2_model
```

Without a restart: keep the pin in `.env` for the next start, and reload the
running gateway with `POST /admin/models/reload` and
`{"l2_model":"guardspec-classifier@<old>"}` (needs `GATEWAY_ADMIN_TOKEN`).
SIGHUP reloads the targets the gateway already has, not a changed `.env`.

Details, the L3 embedder and air-gapped installs:
[docs/models.md](models.md#rolling-back).

### A failed upgrade

- `migrate` exits non-zero: the services do not start (they wait for it).
  `docker compose logs migrate` names the migration. A failed migration
  leaves `schema_migrations.dirty = true`; fix the cause, then restore the
  backup rather than forcing the version.
- `models-init` fails: offline, or a mirror is missing the new version. Set
  `MODELS_MIRROR`, or pin the previous `L2_MODEL` / `L3_MODEL`, and `up`
  again.
- The gateway is unhealthy: `docker compose logs gateway`; with
  `DETECTOR_REQUIRE_ML=true` a missing model stops it at start, by design.
