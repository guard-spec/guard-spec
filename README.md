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

Refused requests return HTTP 400 with `{"error":{"message":"...","type":"invalid_request_error","code":"content_filter"}}`. If policies cannot be loaded or evaluated the gateway returns 503 and sends nothing upstream. Evaluation is bounded: a policy holds at most 200 rules (the control plane refuses more), each rule has a CEL cost limit, all rules of one request share a total cost budget, and evaluation stops when the policy timeout expires. Any of these limits fails closed with 503.

An upstream 4xx is passed to the client with its status and message (a 429 keeps its `Retry-After`). Any upstream 5xx becomes 502 with code `upstream_error`, and its body is not passed on; an upstream that does not answer in time gives 504 with code `upstream_timeout`. If the client hangs up before the upstream answers, the upstream request is cancelled at once rather than at the timeout.

Policy rules run in order. The first matching `allow` or `block` rule decides. A matching `log` rule is recorded (its id goes in the audit row when no later rule decides) and evaluation continues with the next rule.

Each request gets one audit row in `requests`. `action` is `allow`, `block`, `error` (the upstream failed or the client left before it answered) or `output_leak` (the canary showed up in the answer).

## Output guard

The gateway checks the model's answer before the client sees it. It rewrites `choices[].message.content` (and `choices[].text` for legacy completions) in whole responses. In streams it keeps a 256-character window per choice, so a pattern split across chunks is still caught, and rebuilds each chunk with its id, model and other fields unchanged. A stream therefore runs about 256 characters behind the upstream. Held text is flushed at `finish_reason` and at `[DONE]`. An upstream body that is not JSON cannot be checked and gives 502.

What it does:

- **Images and links.** It removes markdown images, HTML `<img>` tags and reference definitions whose host is not on the allowlist (`[REDACTED:image]`). Links to other hosts keep their text and lose the URL. Bare image URLs that carry a query string are replaced with `[REDACTED:url]`. With the default empty allowlist every image and link is removed.
- **Personal data.** It replaces each match with `[REDACTED:<type>]`: `email`, `phone` (Vietnamese numbers in the +84, 84 and 0 forms, mobile and landline), `cccd` (12 digits starting with 0), `card` (13 to 19 digits that pass the Luhn check) and, when enabled, `ipv4`.
- **Canary.** When enabled, the gateway puts a random token for each request in the system prompt (appended to a leading system message, or as a new one; legacy completions have no system prompt and get none). If the model repeats it, the response is refused with 400 `content_filter`, or in a stream an error event that ends it, or the token is redacted. Either way the row's action is `output_leak`.
- **Reasoning.** The `reasoning` and `reasoning_content` fields that Ollama and vLLM send are guarded like the answer, or dropped.

The audit row counts what was removed per type in `pii_entities`, as `output:email=2`. It never stores the content.

There are no per-org settings yet, so these variables apply to every org:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OUTPUT_GUARD` | `on` | `off` passes responses through unchanged |
| `OUTPUT_LINK_ALLOWLIST` | empty | Comma-separated hosts whose images and links are kept. A host also covers its subdomains |
| `OUTPUT_PII_REDACT` | `true` | Redact email, phone, CCCD and card numbers |
| `OUTPUT_PII_IPV4` | `false` | Also redact IPv4 addresses |
| `OUTPUT_CANARY` | `off` | `block` or `redact` injects a canary and acts when it leaks |
| `OUTPUT_REASONING` | `guard` | `drop` removes reasoning fields instead |

## Upgrade notes

**Removed policy fields.** `toxicity.score`, `pii.entities` and `topic.categories` are no longer rule fields, because no detector produced them: they were always 0 or empty. The control plane refuses new rules that name them. Stored rules that name them still evaluate them as 0 or empty, as before, so an upgrade does not make the gateway fail closed with 503 for those orgs. The gateway logs a warning when it compiles one. Before or after upgrading, list the policies that need editing:

```bash
DATABASE_URL=postgres://ps:ps@localhost:5432/promptshield?sslmode=disable \
  go run ./cmd/control-plane -check-policies
```

It checks every stored policy, enabled or not, against the rules for new policies (removed fields, actions the gateway cannot enforce, conditions that do not compile) and prints one `FAIL` line for each problem. It exits 0 when all pass, 1 when any fails, and 2 when it cannot read the policies. Run it as a role that bypasses row-level security, such as the table owner (`ps` in the compose stack); `ps_app` sees no policies outside an org scope. With the compose stack you can also run it from the image: `docker compose run --rm -e DATABASE_URL=postgres://ps:ps@postgres:5432/promptshield?sslmode=disable control-plane -check-policies`.

**Log rules.** A `log` rule used to stop evaluation and allow the request. It now records its match and lets later rules decide, so a `block` after a `log` rule now blocks.

**Audit actions.** Upstream failures used to be recorded as `allow`. They are now `error`.

## Detection Layers

1. **Unicode sanitization** — strips tag block chars, bidi overrides, variation selectors. Defeats 100% ASR emoji smuggling before classification.
2. **ML classifiers** (ONNX, in-process) — concurrent injection + PII + toxicity + topic scoring.
3. **CEL policy engine** — per-tenant rules with 130ns eval latency. JSON rule builder in UI.
4. **Output guard** — strips images and links to hosts off the allowlist, redacts personal data, catches a leaked canary. See [Output guard](#output-guard).

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
