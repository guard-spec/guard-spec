<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# LlamaIndex through Guard Spec

[`main.py`](main.py) uses `OpenAILike` (`llama-index-llms-openai-like`
0.8.1, `llama-index-core` 0.14.25) with `api_base` set to the gateway:
`chat`, `stream_chat`, and a prompt injection.

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080   # the gateway, no /v1
export GUARDSPEC_API_KEY=gs_...                   # a Guard Spec key
export MODEL=llama3.2                             # a model your upstream serves
uv run --frozen main.py
```

Use `OpenAILike`, not `llama_index.llms.openai.OpenAI`: the latter checks the
model name against OpenAI's list, so other models fail before any request.
`is_chat_model=True` sends chat completions; `context_window` has to be given
because `OpenAILike` cannot look it up. A block raises the OpenAI SDK's
`openai.BadRequestError` with `e.code == "content_filter"`.

Embeddings (`OpenAIEmbedding`) do not go through the gateway. In a RAG
pipeline, put retrieved chunks in the chat request as tool results, or scan
them before indexing with `POST /guardrail/scan`: [the RAG example](../rag/)
shows both.

## Expected output

With [the throwaway gateway](../../README.md#throwaway-gateway-for-trying-them-and-for-ci)
(fake model; a real model answers instead):

```text
allowed: (fake model) You said: Name three rivers in Vietnam.
streamed: (fake model) You said: Count from one to five.
blocked: content_filter - Request blocked: prompt injection detected.
```

Exit status 0; 1 when the stream is empty or the injection is not blocked.
