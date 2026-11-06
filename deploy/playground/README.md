<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# Public playground backend

The backend of the playground page on the website (`/playground`): visitors
type a prompt, a retrieved document or an MCP tool description and see what
Guard Spec decides, without installing anything. This directory is a
template for hosting it; nothing here is deployed by the project.

```
browser (guardspec.io/playground)
   │  POST /v1/scan {"text", "kind"}     CORS: ALLOWED_ORIGINS only
   ▼
Caddy (profile tls, optional) ── HTTPS, 64 KB body cap, no access log
   ▼
playground proxy (cmd/playground) ── rate limits, size limits, timeouts,
   │                                  optional Turnstile; holds the API key
   ▼  POST /guardrail/scan or /guardrail/scan/tools, "explain": true
gateway-full (L1 + L2 + L3, models in the image) ── internal network, no egress
   ▼
Postgres in memory (tmpfs) ── the playground org and its key; audit rows dropped
```

## Why a separate proxy, not a playground mode in the gateway

- **The key stays on the server.** The gateway authenticates every
  `/guardrail/*` route with an API key. An unauthenticated mode in the
  gateway would add a code path that skips the key check to the same binary
  that guards production traffic; one configuration mistake would open a
  production gateway. The proxy holds a key of a dedicated `playground` org
  and the gateway keeps its auth unchanged.
- **One route, nothing else.** The proxy serves `POST /v1/scan` and
  `GET /healthz`. It cannot reach the chat routes, the admin routes, policies
  or upstreams, whatever a visitor sends: it builds the gateway request
  itself.
- **Abuse controls live where the client address is known**, in front of
  the gateway: per-IP token buckets, a global budget, a bound on concurrent
  scans, input and body size limits, timeouts, CORS and an optional
  Turnstile check. The gateway's own per-key limit (`RATE_LIMIT_RPM`) stays
  as a backstop.
- **Small.** About 900 lines of Go, standard library only, a 15 MB
  distroless image running as nonroot with a read-only root file system.

## API

`POST /v1/scan`, `Content-Type: application/json`, from an allowed origin:

```json
{"text": "Ignore all previous instructions…", "kind": "prompt"}
```

`kind` is `prompt` (default; `/guardrail/scan` text), `document` (third-party
content, scanned as indirect injection) or `tool` (an MCP tool description,
`/guardrail/scan/tools`). With `TURNSTILE_SECRET` set, add
`"turnstile_token"`. Unknown fields are refused.

```json
{
  "decision": "blocked",
  "kind": "prompt",
  "score": 0.999,
  "label": "direct_injection",
  "decided_by": "l1",
  "reason": "fusion",
  "layers": {"l1": 0.993, "l2": 0.993, "l3": 0.317},
  "rules": ["di.override.chained_qualified", "…"],
  "sanitizer": {"anomaly_score": 0, "bytes_removed": 0, "findings": []},
  "latency_ms": 52
}
```

- `layers` is null when the gateway does not explain (releases up to 0.2.1);
  a layer is null when it did not run.
- `decided_by`: `l1`, `l2`, `l3` (the strongest layer of the fused score),
  `sanitizer` (hidden characters; `label` is then `hidden_characters`) or
  `signals` (MCP poisoning signals). `reason`: `fusion`, `cascade`,
  `l1_floor`, `anomaly` or `mcp_signals`.
- `sanitizer.findings`: `tag_chars`, `bidi`, `removed_chars`. Absent for
  `tool`; `signals` lists the MCP poisoning signals instead.
- The sanitized text is not echoed back.

Errors are `{"error": "<code>", "message": "…"}`: 400 invalid request, 403
`origin_not_allowed` or `challenge_failed`, 413 text over `MAX_INPUT_BYTES`
or body over `MAX_BODY_BYTES`, 415 not JSON, 429 `rate_limited` (with
`Retry-After`), 503 `busy` (global budget, too many clients tracked, or all
`MAX_IN_FLIGHT` slots taken), 502 `scanner_unavailable`.

## Run it

```bash
cd deploy/playground
cp .env.example .env    # fill in the three secrets (commands in the file)
docker compose up -d --build                  # proxy on 127.0.0.1:8090
docker compose --profile tls up -d --build    # + Caddy with HTTPS on 80/443
```

With the `tls` profile, point `PLAYGROUND_HOST` (such as
`play-api.guardspec.io`) at the host, open ports 80 and 443 and set
`CADDY_TLS` to an email address for Let's Encrypt. Then set `api_url` in the
website's `src/playground.json` to `https://<PLAYGROUND_HOST>` and rebuild
the site; until then the page says "Playground coming soon".

The gateway image is `ghcr.io/guard-spec/guard-spec-gateway-full`:
the models are inside, so nothing is downloaded at start and the gateway
needs no network. Per-layer scores need a release that includes the
`explain` field (after 0.2.1); `GATEWAY_IMAGE` picks the image.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PLAYGROUND_GATEWAY_KEY` | (required) | The proxy's gateway key, `gs_` + 32 or more random characters. `bootstrap.sh` stores its SHA-256 for the `playground` org and revokes the org's other keys, so changing it rotates the key |
| `POSTGRES_PASSWORD`, `GUARDSPEC_APP_PASSWORD` | (required) | Database passwords (12+ characters, not defaults) |
| `ALLOWED_ORIGINS` | `https://guardspec.io` | Exact origins allowed to call, comma-separated |
| `ALLOW_NO_ORIGIN` | `false` | Accept requests without an `Origin` header (curl, scripts) |
| `CLIENT_IP_HEADER` | `X-Forwarded-For` in compose | Where the client address is: `X-Forwarded-For` (its last entry) behind the bundled Caddy, `CF-Connecting-IP` behind Cloudflare, `Fly-Client-IP` on Fly.io, empty when clients connect directly. Set it only when a proxy you control sets the header, or clients can pick their own bucket |
| `RATE_PER_MINUTE`, `RATE_PER_DAY` | `10`, `200` | Token buckets per client: IPv4 address or IPv6 /64 |
| `GLOBAL_RATE_PER_MINUTE` | `300` | All clients together; over it: 503 |
| `MAX_TRACKED_CLIENTS` | `100000` | Clients kept in the limiter (idle ones are dropped); over it: 503 |
| `MAX_INPUT_BYTES` | `4096` | Text size; keep the site's `max_input_bytes` the same |
| `MAX_BODY_BYTES` | 6 × input + 1024 | Request body size (JSON escaping can grow text) |
| `MAX_IN_FLIGHT` | `8` | Concurrent gateway calls; over it: 503 |
| `GATEWAY_TIMEOUT` | `5s` | Per gateway call |
| `TURNSTILE_SECRET` | empty (off) | Cloudflare Turnstile secret key |
| `STATS_INTERVAL` | `5m` | How often the counters are logged |
| `GATEWAY_CPUS`, `GATEWAY_MEMORY` | `2`, `1536m` | Gateway limits; the full detector peaks near 950 MiB (docs/sizing.md) |
| `DETECTOR_LAYERS` | `l1,l2,l3` | `l1,l2` halves the gateway's memory and drops L3 |

## Security notes

**Exposed:** only the proxy's `POST /v1/scan` and `GET /healthz` (through
Caddy, or on loopback without it). The gateway and Postgres are on an
internal Docker network without a route out; the gateway has no upstream
LLM configured and the proxy calls nothing but `/guardrail/scan` and
`/guardrail/scan/tools`. The browser never sees an API key.

**Stored or logged:**

- *Prompts:* nowhere. The proxy does not log bodies. The gateway runs with
  `AUDIT_STORE_CONTENT=false`, `SCAN_CACHE_SIZE=0` (no in-memory cache of
  results), `ALERTS_EVENTS=off` and `AUDIT_DEDUPE_WINDOW=0`, and
  `bootstrap.sh` installs a trigger that drops every row inserted into the
  audit table, so not even the SHA-256 or the length of a prompt is kept.
  Postgres runs on tmpfs: a restart starts empty.
- *Client addresses:* held in memory by the rate limiter only, dropped once
  the client is idle (its buckets are full again, at most a day). Never
  logged. Caddy runs without an access log.
- *Logs:* the proxy logs its start, gateway failures (status only) and
  every `STATS_INTERVAL` the counts of allowed, blocked, rate-limited, busy,
  rejected and failed scans. The gateway logs startup and errors.

**Abuse:** the limits above bound one client to 10 scans a minute and 200 a
day, everyone together to 300 a minute, and the gateway to `MAX_IN_FLIGHT`
concurrent scans of at most 4 KB. The playground runs the detector only, so
the worst case is CPU time on this host: no LLM bill, no data to steal.
Visitors can probe the detector for bypasses, as they can with the open
source code; per-layer scores make that easier, which is the point of a
playground. `SCAN_EXPLAIN=false` on the gateway turns them off.

**Turnstile** (off by default): create a widget in the Cloudflare dashboard
for the site's host name, put its secret key in `TURNSTILE_SECRET` and its
site key in the website's `src/playground.json` (`turnstile_sitekey`). The
page then loads Cloudflare's script, renders the widget and sends its token;
the proxy verifies each token with Cloudflare's `siteverify` (which sees the
client address) and refuses the scan without a valid one. Turn it on when
the rate limits are not enough.

## Estimated monthly cost

**Estimates, checked on 2026-11-07, before tax; prices change, confirm them
with the provider.** The stack needs about 1.1 GiB of RAM at rest (gateway
~905 MiB with L1 + L2 + L3, Postgres ~70 MiB, proxy ~3 MiB) and up to 2 vCPUs
while scanning; a scan takes 10 to 60 ms of detector time.

| Host | Size | Estimate | Notes |
|---|---|---|---|
| Hetzner Cloud | 2 vCPU, 4 GB (CX23 class) | about €5–10 / month incl. IPv4 | Cheapest; 20 TB traffic included. The cost-optimized lines were reported hard to order in late 2026; a CPX plan of the same size costs more |
| DigitalOcean | Basic Droplet, 2 vCPU, 4 GB | about $24 / month | Simple; backups +20% (not needed: the stack keeps no state) |
| Fly.io | shared-cpu-2x, 4 GB, always on | about $25 / month | RAM is most of the price ($6 per GB per month since October 2026). Run the compose services as separate Machines or one Machine with a process group; `CLIENT_IP_HEADER=Fly-Client-IP` |
| Google Cloud Run | 2 vCPU, 2 GiB, request-based billing, scales to zero | about $0–10 / month at a few thousand scans a day | Mostly inside the free tier at low traffic, but a cold start loads the models (seconds), and Postgres must be a sidecar container per instance. `min-instances=1` removes cold starts and costs about as much as a small VM or more |

Traffic is negligible: a scan is under 30 KB in and 1 KB out. A domain name
such as `play-api.guardspec.io` is a DNS record on the existing domain.

## Files

| File | What it is |
|---|---|
| `docker-compose.yml` | The stack: proxy, gateway-full, Postgres on tmpfs, migrations, bootstrap, optional Caddy |
| `bootstrap.sh` | App role password, the `playground` org and key, the audit drop trigger |
| `Caddyfile` | HTTPS in front of the proxy (profile `tls`) |
| `.env.example` | Settings to copy into `.env` |
| `../../build/playground.Dockerfile` | The proxy image |
| `../../cmd/playground/` | The proxy's source |
