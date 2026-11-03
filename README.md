# PromptShield

Open-source LLM guardrail backend service. Detects and blocks prompt injection attacks via documents, context, and chat messages.

## Market Context

LLM Guard (Protect AI) was archived 2026-07-09. Rebuff was archived 2025-05-16. PromptShield fills the gap with a containerized, multi-tenant, Apache-2.0 backend service + admin UI.

## Architecture

- **Data plane (Go):** OpenAI-compatible proxy with sanitizer → classifier → CEL policy pipeline. ONNX Runtime in-process via hugot. ~22ms p99 latency on CPU.
- **Control plane (Go):** Management REST API, multi-tenant Postgres, RBAC, policy management.
- **Admin UI (Next.js):** Dashboard, rules config, routing, attack analysis, monitoring.
- **Models:** Apache-2.0 only — Qwen3Guard-Gen-0.6B (fast) + IBM Granite Guardian 3.3 (broad coverage).

## Quick Start

```bash
cp .env.example .env
docker compose up -d
open http://localhost:3000
```

Default admin credentials: admin@localhost / change-on-first-login

## Upstream LLM

The gateway stubs responses until it has an upstream. Set these in `.env` or the environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPSTREAM_LLM_URL` | empty | Base URL of an OpenAI-compatible API, for example `http://host.docker.internal:11434/v1` |
| `UPSTREAM_LLM_KEY` | empty | Bearer token for the upstream. Not sent when empty |
| `UPSTREAM_LLM_TIMEOUT` | `5m` | Longest wait for the first byte, and for any later silence. A long stream is not cut off while data flows |

Refused requests return HTTP 400 with `{"error":{"message":"...","type":"invalid_request_error","code":"content_filter"}}`. If policies cannot be loaded or evaluated the gateway returns 503 and sends nothing upstream.

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
