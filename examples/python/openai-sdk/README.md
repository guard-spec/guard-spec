<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenAI Python SDK through Guard Spec

[`main.py`](main.py) points the official `openai` package (3.37.0) at the
gateway and sends an ordinary question, a streamed one, and a prompt
injection, plain and streamed.

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080   # the gateway, no /v1
export GUARDSPEC_API_KEY=gs_...                   # a Guard Spec key
export MODEL=llama3.2                             # a model your upstream serves
uv run --frozen main.py
```

The only changes from a direct OpenAI client are `base_url` (the gateway plus
`/v1`) and `api_key` (the Guard Spec key; the gateway calls the model with its
own). A blocked request is HTTP 400:

```json
{"error":{"message":"Request blocked: prompt injection detected.","type":"invalid_request_error","code":"content_filter"}}
```

The SDK raises `openai.BadRequestError` with `e.code == "content_filter"` and
does not retry it. A blocked stream fails the same way, before the first
chunk. Catch it, tell the user, and do not resend the same text.

## Expected output

With [the throwaway gateway](../../README.md#throwaway-gateway-for-trying-them-and-for-ci)
(its fake model repeats the prompt; a real model answers instead):

```text
allowed: (fake model) You said: Name three rivers in Vietnam.
streamed: (fake model) You said: Count from one to five.
blocked: content_filter - Request blocked: prompt injection detected.
blocked (streaming): content_filter - Request blocked: prompt injection detected.
```

Exit status 0; 1 (with a `FAIL:` line) when the stream is empty or an
injection is not blocked.
