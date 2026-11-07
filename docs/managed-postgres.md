<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Managed PostgreSQL: RDS, Cloud SQL, Neon, Supabase

> Tiếng Việt: [managed-postgres.vi.md](managed-postgres.vi.md).

> **Status: reference, not yet verified by the maintainers on these
> providers.** Community-tested: not yet. If you run Guard Spec on one of
> them, please open an
> [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a pull
> request with what worked and what did not; contributions are welcome. See
> [CONTRIBUTING.md](../CONTRIBUTING.md).

The compose files and CI use PostgreSQL 17; older versions have not been
tested. Any provider should work if it gives you the roles and extensions
below. This page
covers what the migrations need, the connection string and TLS, and how to
run the [production compose](../deploy/compose/production/README.md) without
its own `postgres` service. For Kubernetes the same database steps apply; see
[docs/deploy/](deploy/README.md).

**What the maintainers checked** (2026-11-06, locally, not on a provider):
a PostgreSQL 17 container standing in for a managed one, where the owner role
`gsowner` is **not** a superuser but has `CREATEROLE` and owns the database,
as on RDS, Cloud SQL, Neon and Supabase. As that role, all migrations
applied, `set-app-password.sh` worked, the production compose with
`managed-postgres.yml` came up healthy, an injection was blocked and a benign
prompt passed over HTTPS. A second database on the same server failed at
migration 004 with `role "guardspec_app" already exists` (see below). TLS to
the database was not part of that test.

## What the database needs

| Need | Why | Notes |
|---|---|---|
| An **owner role** that runs the migrations and owns every table | The services run as `guardspec_app`, which does not own the tables, so row-level security applies to it. A few `SECURITY DEFINER` functions (API key lookup, invites, alerts) run as the owner and must bypass RLS, which a table owner does. | The provider's admin user, or a role you create for Guard Spec. Not a superuser. |
| `CREATEROLE` on the owner role | Migration 004 runs `CREATE ROLE guardspec_app LOGIN`; migration 005 and `set-app-password.sh` run `ALTER ROLE guardspec_app ...` | On PostgreSQL 16 and newer, the role that created `guardspec_app` keeps the right to alter it. |
| Extensions `pgcrypto` and `pg_trgm` | Migration 001 (`CREATE EXTENSION IF NOT EXISTS`) | Both are "trusted" extensions: the database owner may create them without being a superuser. All four providers offer them. |
| The `public` schema, writable by the owner | Tables, functions and `schema_migrations` live there | On PostgreSQL 15+, `public` is writable by the database owner only, which is what you want. |

**`guardspec_app` is cluster-wide.** Roles belong to the whole server
(instance, cluster), not to one database, and migration 004 creates the
role with a fixed name. So:

- one Guard Spec install per server: a second install on the same instance
  (a staging database next to production, say) fails at migration 004 with
  `role "guardspec_app" already exists`. Give staging its own instance, Neon
  project or Supabase project;
- restoring a dump into a new instance needs the role first (`pg_dump` of a
  database does not carry roles): `CREATE ROLE guardspec_app LOGIN;` as the
  owner role, then `pg_restore`. `scripts/restore.sh` does this for compose.

## Connection strings and TLS

The services read `DATABASE_URL` and take the password from `PGPASSWORD`
(compose passes `GUARDSPEC_APP_PASSWORD`), so the URL holds no secret:

```text
DATABASE_URL=postgres://guardspec_app@<host>:5432/guardspec?sslmode=verify-full
```

The gateway and control plane use pgx, which takes the libpq parameters
`sslmode` (`require`, `verify-ca`, `verify-full`), `sslrootcert`, `sslcert`
and `sslkey`. With `verify-full` and no `sslrootcert`, the system's CA
bundle is used: that works when the provider's certificate chains to a
public CA (Neon, according to its documentation) and not when it uses its
own CA (RDS, Cloud SQL, Supabase), whose CA file you then mount and name:

```yaml
# deploy/compose/production/managed-postgres.yml, under gateway and control-plane:
    volumes:
      - ./db-ca.pem:/etc/guardspec/db-ca.pem:ro
# .env:
# DATABASE_URL=postgres://guardspec_app@<host>:5432/guardspec?sslmode=verify-full&sslrootcert=/etc/guardspec/db-ca.pem
```

`sslmode=require` encrypts without checking the server's identity; use it
only to get started.

## Provider notes

### Amazon RDS for PostgreSQL

- Owner: the master user (member of `rds_superuser`, has `CREATEROLE`), or
  a dedicated role it creates: `CREATE ROLE gsowner LOGIN CREATEROLE
  PASSWORD '...'; CREATE DATABASE guardspec OWNER gsowner;`
- TLS: RDS for PostgreSQL 15 and newer sets `rds.force_ssl=1`. Download the
  region's CA bundle (`global-bundle.pem` from the RDS documentation) and use
  `sslmode=verify-full&sslrootcert=...`.
- Host: the instance endpoint, `<name>.<id>.<region>.rds.amazonaws.com`.
  Through RDS Proxy, see "Poolers" below.
- More: [docs/deploy/aws.md](deploy/aws.md).

### Google Cloud SQL for PostgreSQL

- Owner: the `postgres` user (member of `cloudsqlsuperuser`, has
  `CREATEROLE`), or a user you create in the console or with
  `gcloud sql users create` and then make the database owner.
- TLS: either connect to the instance IP with the server CA certificate from
  the console (`sslmode=verify-ca` with that file: Cloud SQL's server
  certificates do not always carry the host name), or run the Cloud SQL Auth
  Proxy next to the services and connect to it with `sslmode=disable` (the
  proxy encrypts).
- More: [docs/deploy/gcp.md](deploy/gcp.md).

### Neon

- Owner: the role Neon creates with the project (member of
  `neon_superuser`, has `CREATEROLE`).
- TLS: required; certificates chain to a public CA, so `sslmode=verify-full`
  works without `sslrootcert`.
- Use the **direct** endpoint (host without `-pooler`) for migrations and
  for the services (see "Poolers").
- Scale-to-zero: the first query after an idle period waits for the compute
  to start. For production, turn auto-suspend off or keep a minimum compute
  size, or the first requests after a quiet period are slow.

### Supabase

- Owner: the `postgres` user (has `CREATEROLE`, is not a superuser).
- `pgcrypto` is already installed (in the `extensions` schema); migration 001
  leaves it there and creates `pg_trgm`.
- Connection: the direct connection (`db.<project>.supabase.co:5432`) or the
  pooler in session mode (port 5432 on the pooler host); not transaction
  mode (port 6543), see "Poolers". The direct host may be IPv6 only, which
  Docker networks often lack; the session pooler has IPv4.
- TLS: Supabase uses its own CA (download it from the project's database
  settings); `sslmode=verify-full&sslrootcert=...`.
- Guard Spec only needs the database: the Supabase API, auth and storage stay
  unused. Do not expose Guard Spec's tables through the Supabase REST API:
  they belong to the owner role and live in `public`, which the API serves by
  default, so check the API's exposed schemas.

### Poolers

The services keep their own connection pools and use prepared statements
and transactions that set `app.org_id` for row-level security. Connect them
directly, or through a pooler in **session** mode. Transaction-mode pooling
(PgBouncer `pool_mode=transaction`, Supabase port 6543, RDS Proxy pinning
behaviour) has not been tested and is likely to break prepared statements or
the per-transaction settings.

## Running the migrations

As the owner role, from a checkout of the release you deploy (the
`migrations/` directory must match the images' version):

```bash
export DB_HOST=<host>
export OWNER=<owner role>
export PGPASSWORD=<owner password>
export PARAMS='sslmode=verify-full'   # add &sslrootcert=/ca/<file> with -v "$PWD/<file>:/ca/<file>:ro"

docker run --rm -e PGPASSWORD -v "$PWD/migrations:/migrations:ro" \
  migrate/migrate:v4.20.1 -path=/migrations \
  -database "postgres://$OWNER@$DB_HOST:5432/guardspec?$PARAMS" up
```

Then set the application role's password (it has none after the migrations;
run this again to rotate it):

```bash
export GUARDSPEC_APP_PASSWORD=<openssl rand -hex 24>
docker run --rm -e PGHOST="$DB_HOST" -e PGUSER="$OWNER" -e PGDATABASE=guardspec \
  -e PGPASSWORD -e PGSSLMODE=verify-full -e GUARDSPEC_APP_PASSWORD \
  -v "$PWD/deploy/postgres/set-app-password.sh:/set-app-password.sh:ro" \
  postgres:17.11-alpine sh /set-app-password.sh
# guardspec_app password set
```

`set-app-password.sh` refuses weak or default passwords (also for the owner,
in `PGPASSWORD`). Run both steps again on every upgrade, before the new
images start ([docs/upgrade.md](upgrade.md)); the migrate tool applies only
what is new.

## The production compose without its database

[`deploy/compose/production/managed-postgres.yml`](../deploy/compose/production/managed-postgres.yml)
moves the `postgres`, `migrate` and `db-roles` services behind a profile and
points the gateway and control plane at `DATABASE_URL`:

```bash
cd deploy/compose/production
# .env: DATABASE_URL=..., GUARDSPEC_APP_PASSWORD (the one set above), and
# POSTGRES_PASSWORD set to any long value (unused, but required by the file)
docker compose -f docker-compose.yml -f managed-postgres.yml up -d --wait
```

The gateway and control plane are on the `edge` network, which has a route
out; the database must accept connections from the host's address
(security group, authorized networks, IP allow list).

## Backups

`scripts/backup.sh` dumps the compose `postgres` service and does not apply
here. Use the provider's automated backups and point-in-time recovery, and
keep `.env` (`MFA_ENC_KEY` above all: the 2FA secrets in the database are
encrypted with it) with the same care. A logical dump as well:

```bash
docker run --rm -e PGPASSWORD postgres:17.11-alpine \
  pg_dump -Fc "postgres://$OWNER@$DB_HOST:5432/guardspec?$PARAMS" > guardspec.dump
```

Restoring a snapshot into a new instance brings the roles with it; restoring
a dump does not (create `guardspec_app` first, as above, then run
`set-app-password.sh`).
