# PromptShield

Open-source LLM guardrail backend service. Detects and blocks prompt injection attacks via documents, context, and chat messages.

## Market Context

LLM Guard (Protect AI) was archived 2026-07-09. Rebuff was archived 2025-05-16. PromptShield fills the gap with a containerized, multi-tenant, Apache-2.0 backend service + admin UI.

## Architecture

- **Data plane (Go):** OpenAI-compatible proxy with sanitizer → classifier → CEL policy pipeline. ONNX Runtime in-process via hugot. ~22ms p99 latency on CPU.
- **Control plane (Go):** Management REST API, multi-tenant Postgres, RBAC, policy management.
- **Admin UI (Next.js):** Dashboard, rules config, routing, attack analysis, monitoring.
- **Models:** Apache-2.0 only — Qwen3Guard-Gen-0.6B (fast) + IBM Granite Guardian 3.3 (broad coverage).

## Quick Start (local development)

```bash
docker compose up -d
```

`docker compose up` also loads `docker-compose.override.yml`, which sets
`GUARD_ENV=dev` and well-known throwaway credentials (admin login
`admin@localhost` / `change-on-first-login`). Never deploy with it.

## Production

```bash
cp .env.example .env      # fill in every secret, e.g. with: openssl rand -hex 32
docker compose -f docker-compose.yml up -d
```

Outside `GUARD_ENV=dev` the services refuse to start while a secret is missing,
a known default (any value shipped in this repository) or too short, and the
error names the variable to set:

| Variable | Used by | Requirement |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | postgres, migrations | at least 12 characters, not a default |
| `PS_APP_PASSWORD` | gateway, control plane (role `ps_app`) | at least 12 characters, not a default; applied by the `db-roles` service on every start |
| `JWT_SECRET` | control plane | at least 32 bytes, not a default |
| `ADMIN_PASSWORD` | control plane, with `ADMIN_EMAIL` | at least 12 characters, not a default; the first owner is created only when both are set |

Migration 004 no longer contains a password for `ps_app`, and migration 005
clears the one earlier versions set. Outside compose, set it yourself after
migrating: `PS_APP_PASSWORD=... sh deploy/postgres/set-app-password.sh` with
superuser credentials in `PGHOST`, `PGUSER`, `PGDATABASE` and `PGPASSWORD`.

## Audit privacy

Audit rows (`requests`) store scores, the decision, and a SHA-256 and the
length of the request body and of a buffered upstream response. They store no
prompt or response content unless content storage is enabled, either for every
organization with `AUDIT_STORE_CONTENT=true` on the gateway, or for one
organization with `PATCH /v1/organizations/{id}` and
`{"audit_store_content": true}` (admin role). Streamed responses are not
buffered, so their response columns stay empty.

## Upstream LLM

The gateway stubs responses until it has an upstream. Set these in `.env` or the environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPSTREAM_LLM_URL` | empty | Base URL of an OpenAI-compatible API, for example `http://host.docker.internal:11434/v1` |
| `UPSTREAM_LLM_KEY` | empty | Bearer token for the upstream. Not sent when empty |
| `UPSTREAM_LLM_TIMEOUT` | `5m` | Longest wait for the first byte, and for any later silence. A long stream is not cut off while data flows |

Refused requests return HTTP 400 with `{"error":{"message":"...","type":"invalid_request_error","code":"content_filter"}}`. If policies cannot be loaded or evaluated the gateway returns 503 and sends nothing upstream. Evaluation is bounded: a policy holds at most 200 rules (the control plane refuses more), each rule has a CEL cost limit, all rules of one request share a total cost budget, and evaluation stops when the policy timeout expires. Any of these limits fails closed with 503.

An upstream 4xx is passed to the client with its status and message (a 429 keeps its `Retry-After`). Any upstream 5xx becomes 502 with code `upstream_error`, and its body is not passed on; an upstream that does not answer in time gives 504 with code `upstream_timeout`.

## Detection Layers

1. **Unicode sanitization** — strips tag block chars, bidi overrides, variation selectors. Defeats 100% ASR emoji smuggling before classification.
2. **ML classifiers** (ONNX, in-process) — concurrent injection + PII + toxicity + topic scoring.
3. **CEL policy engine** — per-tenant rules with 130ns eval latency. JSON rule builder in UI.
4. **Output guard** — strips untrusted links/images, PII redaction, egress URL allowlist.

## License

Apache-2.0. See [NOTICE](NOTICE) for dependency licenses.

**Blocked model families (not included):**
- Llama Guard / Prompt Guard: Llama Community License
- ShieldGemma: Gemma Terms of Use
- NVIDIA NeMoGuard: NVIDIA Open Model License

## Development

```bash
# Start dependencies
docker compose up postgres clickhouse -d

# Download models
python cmd/model-init/download.py --models qwen3guard-gen-0.6b

# Build and run gateway (Linux/WSL required for ORT)
make build
./bin/gateway

# Run tests
make test
```

See [DESIGN.md](DESIGN.md) for the full architecture documentation.
