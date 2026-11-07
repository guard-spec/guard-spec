<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenAI TypeScript SDK through Guard Spec

[`src/main.ts`](src/main.ts) points the official `openai` package (7.43.0)
at the gateway: a chat, a streamed chat, and a prompt injection, plain and
streamed. Node.js 22 or newer (the SDK requires it); `tsx` runs the
TypeScript directly.

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080   # the gateway, no /v1
export GUARDSPEC_API_KEY=gs_...                   # a Guard Spec key
export MODEL=llama3.2                             # a model your upstream serves
npm ci
npm start              # npm run typecheck checks the types
```

`baseURL` is the gateway plus `/v1`, `apiKey` the Guard Spec key. A block is
HTTP 400 with `error.code` `content_filter`; the SDK throws
`OpenAI.BadRequestError` (`e.code === "content_filter"`, the gateway's
message in `e.error.message`) and does not retry it. A blocked stream throws
the same error from `create()`, before the first chunk.

## Expected output

With [the throwaway gateway](../../README.md#throwaway-gateway-for-trying-them-and-for-ci)
(fake model; a real model answers instead):

```text
allowed: (fake model) You said: Name three rivers in Vietnam.
streamed: (fake model) You said: Count from one to five.
blocked: content_filter - Request blocked: prompt injection detected.
blocked (streaming): content_filter - Request blocked: prompt injection detected.
```

Exit status 0; 1 (with a `FAIL:` line) when the stream is empty or an
injection is not blocked.
