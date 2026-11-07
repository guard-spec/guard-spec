<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Vercel AI SDK through Guard Spec

[`src/main.ts`](src/main.ts) uses the AI SDK (`ai` 7.0.152) with the OpenAI
provider (`@ai-sdk/openai` 4.0.101) created with `baseURL` set to the gateway:
`generateText`, `streamText`, and a prompt injection through both. Node.js 22
or newer.

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080   # the gateway, no /v1
export GUARDSPEC_API_KEY=gs_...                   # a Guard Spec key
export MODEL=llama3.2                             # a model your upstream serves
npm ci
npm start              # npm run typecheck checks the types
```

```ts
const guardspec = createOpenAI({ baseURL: `${process.env.GUARDSPEC_BASE_URL}/v1`, apiKey: process.env.GUARDSPEC_API_KEY });
const model = guardspec.chat(process.env.MODEL ?? "llama3.2");
```

Use `guardspec.chat(...)`: the provider's default, `guardspec(model)`, calls
the Responses API, which the gateway does not serve (404).

Errors:

- `generateText` throws `APICallError` with `statusCode` 400; the gateway's
  JSON is parsed into `e.data` (`{ error: { code: "content_filter", message } }`)
  and `isRetryable` is false.
- `streamText` does not throw. The same `APICallError` arrives as an
  `{ type: "error" }` part of `fullStream` (and in `onError`), so read
  `fullStream` rather than `textStream` when you need it. Without an `onError` option the SDK logs the whole error
  to the console, so pass one when you handle errors yourself.

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
