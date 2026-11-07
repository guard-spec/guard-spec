<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# LangChain through Guard Spec

[`main.py`](main.py) uses `ChatOpenAI` from `langchain-openai` (1.7.2) with
`base_url` set to the gateway: `invoke`, `stream`, and a prompt injection.

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080   # the gateway, no /v1
export GUARDSPEC_API_KEY=gs_...                   # a Guard Spec key
export MODEL=llama3.2                             # a model your upstream serves
uv run --frozen main.py
```

A block reaches your code as the OpenAI SDK's `openai.BadRequestError`
(`e.code == "content_filter"`); LangChain does not wrap it. `max_retries=0`
only keeps the example quick: the SDK does not retry a 400 anyway.

Keep LangChain on chat completions (`use_responses_api=False`, the default
unless you use built-in tools such as web search): the gateway serves the
Responses API only to an upstream that has it (OpenAI, Azure OpenAI), not to
the example's Ollama-style model. `OpenAIEmbeddings` goes through
`/v1/embeddings`, forwarded without scanning unless the gateway sets
`EMBEDDINGS_SCAN=on`. Agents and tool calling work, and the
gateway scans the tool results the agent sends back (see [the RAG
example](../rag/)).

## Expected output

With [the throwaway gateway](../../README.md#throwaway-gateway-for-trying-them-and-for-ci)
(fake model; a real model answers instead):

```text
allowed: (fake model) You said: Name three rivers in Vietnam.
streamed: (fake model) You said: Count from one to five.
blocked: content_filter - Request blocked: prompt injection detected.
```

Exit status 0; 1 when the stream is empty or the injection is not blocked.
