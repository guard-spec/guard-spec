<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Examples

Runnable examples of applications that send their model calls through the
Guard Spec gateway. Each one shows an allowed request, a streamed one, and a
request the gateway blocks, and exits 1 when the gateway does not do what the
example expects.

| Example | What it shows |
|---|---|
| [python/openai-sdk](python/openai-sdk/) | OpenAI Python SDK: chat, streaming, catching the HTTP 400 `content_filter` block |
| [python/langchain](python/langchain/) | LangChain `ChatOpenAI` (`langchain-openai`) pointed at the gateway |
| [python/llamaindex](python/llamaindex/) | LlamaIndex `OpenAILike` pointed at the gateway |
| [python/rag](python/rag/) | A RAG pipeline with a poisoned document: blocked (`INDIRECT_ACTION=block`), redacted (`redact`), or dropped at ingest with `POST /guardrail/scan` |
| [typescript/openai-sdk](typescript/openai-sdk/) | OpenAI TypeScript SDK: chat, streaming, error handling |
| [typescript/vercel-ai-sdk](typescript/vercel-ai-sdk/) | Vercel AI SDK (`@ai-sdk/openai` with `baseURL`): `generateText`, `streamText`, error handling |
| [n8n](n8n/) | An importable n8n workflow: HTTP Request node and OpenAI Chat Model node pointed at the gateway |

Dependencies are pinned: `pyproject.toml` and `uv.lock` for Python (run with
[uv](https://docs.astral.sh/uv/)), `package.json` and `package-lock.json` for
TypeScript (Node.js 22 or newer).

## Configuration

Every example reads the same variables:

| Variable | Example | |
|---|---|---|
| `GUARDSPEC_BASE_URL` | `http://localhost:8080` | The gateway, without `/v1` (a trailing `/v1` is accepted and dropped) |
| `GUARDSPEC_API_KEY` | `gs_...` | A Guard Spec key: the admin UI (API keys) or `POST /v1/organizations/{id}/api-keys`. Never your provider's key |
| `MODEL` | `llama3.2` | A model your upstream (`UPSTREAM_LLM_URL`) serves; the gateway passes the name on |

No key is stored in this directory. Put yours in the environment:

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080
export GUARDSPEC_API_KEY=gs_...        # your key
export MODEL=llama3.2
cd examples/python/openai-sdk && uv run --frozen main.py
```

## Against your own gateway

Start Guard Spec with the [quick start](../README.md#quick-start) and point
`UPSTREAM_LLM_URL` at a model (Ollama, OpenAI, vLLM...); create a key in the
admin UI. The RAG example's query step depends on the gateway's
`INDIRECT_ACTION` (default `block`; `redact` shows the other path).

Without an upstream the gateway answers allowed requests with a fixed stub
message (`[guardrail passed — configure UPSTREAM_LLM_URL ...]`) as plain JSON,
also when the client asked for a stream; the streaming examples need an
upstream, real or the fake one below.

## Throwaway gateway for trying them (and for CI)

[`dev/start.sh`](dev/start.sh) starts everything the examples need from this
checkout, without the admin UI and without downloading models:

- Postgres with the migrations (`docker compose`, project `gs-examples`,
  development credentials, port 55432);
- [`dev/fake_upstream.py`](dev/fake_upstream.py), an OpenAI-compatible fake
  model (standard library only) whose answer repeats what it received, so you
  can see what reached the model through the gateway;
- the gateway built with `go build ./cmd/gateway`, rule layer only
  (`DETECTOR_LAYERS=l1`), twice: `INDIRECT_ACTION=block` on port 18180 and
  `INDIRECT_ACTION=redact` on port 18181;
- a random key for this run, written with the URLs to `dev/.state/env`.

```bash
examples/dev/start.sh            # needs docker compose v2, Go, python3
examples/dev/run-all.sh          # every example; needs uv and Node.js 22
examples/dev/stop.sh             # stops it and deletes the database volume
```

To run one example by hand, load the variables first:
`set -a; . examples/dev/.state/env; set +a`. Setting `UPSTREAM_LLM_URL` before
`start.sh` uses a real model instead of the fake one. Development only: the
database password is the well-known one of `docker-compose.override.yml`.

The [Examples workflow](../.github/workflows/examples.yml) runs `start.sh`
and `run-all.sh` on pull requests that touch the examples or the gateway. It
is not a required check.
