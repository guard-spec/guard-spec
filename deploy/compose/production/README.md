<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Production compose with Caddy

> Tiếng Việt: [README.vi.md](README.vi.md).

One host, Docker Compose, HTTPS. For a startup or a team that wants Guard Spec
on a single VM without Kubernetes. The quick start
([`docker-compose.yml`](../../../docker-compose.yml) at the repository root)
publishes every port over plain HTTP; this stack does not.

| | Quick start (root) | This stack |
|---|---|---|
| Published ports | 8080, 9090, 18081, 9091 (plain HTTP) | 80 and 443 (Caddy) only |
| TLS | none | Caddy: automatic HTTPS (Let's Encrypt, ZeroSSL) or its internal CA |
| Limits | none | CPU and memory per service, sized from [docs/sizing.md](../../../docs/sizing.md) |
| Logs | Docker defaults (unbounded) | json-file, 10 MB x 5 per container |
| Restart | none | `unless-stopped` |
| Health checks | gateway | every long-running service; Caddy starts after the gateway and control plane are healthy |
| Missing models | warn, run on L1 | refuse to start (`DETECTOR_REQUIRE_ML=true`) |
| Postgres | default network | internal network, no route outside |

```text
internet ──443──> caddy ──> gateway:8080        (GATEWAY_HOST)
                        └─> control-plane:8081  (ADMIN_HOST: admin UI at /ui/, API at /v1)
                   edge network                  backend network (internal)
                   gateway, control-plane ─────> postgres
```

## Start

You need a host with Docker and Compose v2, this repository (or a release
source archive: the stack uses `migrations/` and
`deploy/postgres/set-app-password.sh` from it), and two DNS names pointing at
the host, with ports 80 and 443 open.

```bash
cd deploy/compose/production
cp .env.example .env && chmod 600 .env
# Fill in .env: GATEWAY_HOST, ADMIN_HOST, CADDY_TLS=<your email>, and every
# secret (openssl rand -hex 24 for passwords, openssl rand -hex 32 for
# JWT_SECRET, openssl rand -base64 32 for MFA_ENC_KEY), ADMIN_EMAIL and
# ADMIN_PASSWORD.
docker compose up -d --wait
```

The first start pulls the images and the models (about 270 MB; 135 MB with
`DETECTOR_LAYERS=l1,l2`), runs the migrations, and Caddy gets certificates for
both names. Then:

```bash
curl -s https://$GATEWAY_HOST/readyz      # "layers":["l1","l2","l3"]
open https://$ADMIN_HOST/ui/              # log in with ADMIN_EMAIL / ADMIN_PASSWORD
```

Create an API key in the admin UI (or with the API, as in the
[README quick start](../../../README.md#quick-start), with
`https://$ADMIN_HOST/v1` instead of `http://localhost:18081/v1`), and point
your applications at `https://$GATEWAY_HOST/v1`
([docs/integrations.md](../../../docs/integrations.md)).

## Testing with Caddy's internal CA

Without public DNS (a laptop, a private network, CI), let Caddy issue
certificates from its own CA:

```bash
# .env
GATEWAY_HOST=gw.localhost
ADMIN_HOST=admin.localhost
CADDY_TLS=internal
HTTPS_PORT=8443        # if 443 is taken
HTTP_PORT=8480
```

```bash
docker compose up -d --wait
# Either skip verification ...
curl -sk --resolve gw.localhost:8443:127.0.0.1 https://gw.localhost:8443/readyz
# ... or trust Caddy's root certificate.
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
curl -s --cacert caddy-root.crt --resolve gw.localhost:8443:127.0.0.1 https://gw.localhost:8443/readyz
```

Clients then need `caddy-root.crt` (Python: `SSL_CERT_FILE` or
`REQUESTS_CA_BUNDLE`; Node: `NODE_EXTRA_CA_CERTS`). The root lives in the
`caddy_data` volume and is kept by `scripts/backup.sh`. With a port other
than 443, Caddy's HTTP-to-HTTPS redirect points at port 443; use the HTTPS
port directly.

## Settings

Everything is in `.env` ([`.env.example`](.env.example) lists it):

| Variable | Default | Notes |
|---|---|---|
| `GATEWAY_HOST`, `ADMIN_HOST` | required | Two names; the control plane is not served on the gateway's name |
| `CADDY_TLS` | required | Your email (ACME) or `internal` |
| `ADMIN_ALLOW` | `0.0.0.0/0 ::/0` | Client ranges allowed on `ADMIN_HOST`, such as your VPN. Needs Docker to pass real client addresses (Linux default; not Docker Desktop) |
| `DETECTOR_LAYERS` | `l1,l2,l3` | `l1,l2` is light mode ([docs/sizing.md](../../../docs/sizing.md)) |
| `GATEWAY_CPUS`, `GATEWAY_MEMORY` | `2`, `2g` | Measured peaks: full detector 0.9 GiB, light 0.5 GiB |
| `INFERENCE_MAX_CONCURRENCY`, `INFERENCE_INTRA_OP_THREADS` | `2`, `1` | Model runs at once x threads each; keep the product at or below `GATEWAY_CPUS` |
| `MAX_SCAN_TOKENS`, `INFERENCE_LARGE_MAX_CONCURRENCY`, `LARGE_SCAN_QUEUE_TIMEOUT` | unset (today's limits), `GATEWAY_CPUS` / 4 (at least 1), `30s` | Large inputs: the token cap that opens the long path, large requests scanned at once, and how long one waits before 429. See [Large inputs](../../../README.md#large-inputs) |
| `CONTROL_PLANE_CPUS`, `CONTROL_PLANE_MEMORY` | `1`, `256m` | |
| `POSTGRES_CPUS`, `POSTGRES_MEMORY` | `2`, `1g` | |
| `CADDY_CPUS`, `CADDY_MEMORY` | `1`, `256m` | |
| `LOG_MAX_SIZE`, `LOG_MAX_FILE` | `10m`, `5` | Per container |
| `EDGE_SUBNET` | `172.30.89.0/24` | The control plane trusts `X-Forwarded-For` from it (Caddy); change it if it collides with your networks |
| `GUARDSPEC_VERSION` | `0.8.0` | Image tag ([docs/upgrade.md](../../../docs/upgrade.md)) |

`UPSTREAM_KEY_ORGS` has no default here (the quick start lets every org use
`UPSTREAM_KEY_MAIN`), and `UPSTREAM_ALLOW_PRIVATE` is `false`: set them
deliberately, as the [README's Routing section](../../../README.md#routing)
explains.

Metrics (gateway `:9090`, control plane `:9091`) are not published. Run
Prometheus on the `edge` network (`<project>_edge`) and scrape
`gateway:9090` and `control-plane:9091`.

## Operations

- Backups: `scripts/backup.sh -f deploy/compose/production/docker-compose.yml`
  from the repository root, restore with `scripts/restore.sh`
  ([docs/upgrade.md](../../../docs/upgrade.md#backups)).
- Upgrades and rollback: [docs/upgrade.md](../../../docs/upgrade.md).
- Sizing: [docs/sizing.md](../../../docs/sizing.md).
- A managed database instead of the `postgres` service:
  [docs/managed-postgres.md](../../../docs/managed-postgres.md).
- Logs: `docker compose logs -f gateway`; Caddy logs one JSON line per
  request (no bodies).

## What was checked

On an Apple Silicon (arm64) Mac with Docker Desktop, with `CADDY_TLS=internal`:
the stack starts healthy with only Caddy publishing ports; `/readyz` reports
`l1,l2,l3` over HTTPS, verified against Caddy's exported root; a benign prompt
passes (200), an injection is blocked (400), the admin UI loads; a backup
restored into a fresh compose project keeps the organization, users, API keys,
policies, audit rows and Caddy's CA. Automatic HTTPS with a public ACME CA
was not exercised (it needs public DNS); the Caddyfile adapts to an ACME
policy for both names (`caddy adapt`).
