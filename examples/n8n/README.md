<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# n8n through Guard Spec

[`guardspec-workflow.json`](guardspec-workflow.json) is an n8n workflow you
import. It sends two prompts, an ordinary question and a prompt injection,
to the gateway two ways:

- **HTTP Request** node: `POST {baseUrl}/v1/chat/completions` with a Header
  Auth credential. *Never Error* is on, so a block (HTTP 400) reaches the
  next node, and **HTTP verdict** reads `error.code` `content_filter` and the
  gateway's message.
- **Basic LLM Chain** with the **OpenAI Chat Model** node, whose OpenAI
  credential has its Base URL set to the gateway. *On Error: Continue* turns a
  block into an item with an `error` field; **OpenAI verdict** marks it.

Checked with n8n 2.46.6 (`n8nio/n8n:2.46.6`, CLI import and execute).

## Steps

1. **Credentials** (n8n: Credentials, Add credential). No key is in the
   workflow file; it refers to two credentials by name:
   - *Header Auth*, named `Guard Spec API key`: Name `Authorization`, Value
     `Bearer gs_...` (your `GUARDSPEC_API_KEY`).
   - *OpenAI*, named `Guard Spec gateway (OpenAI)`: API Key `gs_...`, Base URL
     the gateway plus `/v1` (`GUARDSPEC_BASE_URL/v1`), e.g.
     `http://host.docker.internal:8080/v1` when n8n runs in Docker and the
     gateway on the host.
2. **Import**: Workflows, Import from File, `guardspec-workflow.json`
   (or `n8n import:workflow --input=guardspec-workflow.json`). Open the two
   nodes with credentials and pick the ones from step 1 if n8n did not match
   them by name.
3. **Config** node: set `baseUrl` to the gateway (`GUARDSPEC_BASE_URL`,
   without `/v1`) and `model` to a model your upstream serves.
4. **Execute workflow.**

The OpenAI Chat Model node has *Use Responses API* off: the gateway serves
chat completions, not the Responses API.

## Expected output

**HTTP verdict** and **OpenAI verdict**, with [the throwaway
gateway](../README.md#throwaway-gateway-for-trying-them-and-for-ci) (fake
model; a real model answers instead):

```json
{"case": "ordinary question", "verdict": "allowed", "answer": "(fake model) You said: Name three rivers in Vietnam."}
{"case": "prompt injection", "verdict": "blocked", "code": "content_filter", "message": "Request blocked: prompt injection detected."}
```

```json
{"case": "ordinary question", "verdict": "allowed", "answer": "(fake model) You said: Name three rivers in Vietnam."}
{"case": "prompt injection", "verdict": "blocked", "message": "Bad request - please check your parameters"}
```

n8n's OpenAI node replaces the gateway's message with its own for an HTTP
400, so the OpenAI branch cannot tell a block from another bad request. Use
the HTTP Request node where the reason matters.

## Check the file

CI does not run n8n; [`validate.py`](validate.py) checks the shape n8n's
import needs (nodes, connections, credentials by reference only, no key in
the file) and that a block is handled rather than failing the run:

```bash
python3 validate.py
```
