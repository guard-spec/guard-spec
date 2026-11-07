# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""A fake OpenAI-compatible model for running the examples without a real one.

It serves POST /v1/chat/completions (plain and streamed), POST /v1/completions
and GET /v1/models with the Python standard library only. Its answer
describes what it received, so the examples can show what reached the model
through Guard Spec: the last user message, and the content of every tool
result (a retrieved document, or Guard Spec's placeholder when it was
redacted).

    python3 examples/dev/fake_upstream.py --port 18199

Then start the gateway with UPSTREAM_LLM_URL=http://127.0.0.1:18199/v1.
Not a model: never point anything but these examples at it.
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def text_of(content):
    """The text of a message's content (a string or a list of parts)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def answer(messages):
    tool_results = [text_of(m.get("content")) for m in messages if m.get("role") == "tool"]
    users = [text_of(m.get("content")) for m in messages if m.get("role") == "user"]
    if tool_results:
        shown = "; ".join(f"[{t[:100]}]" for t in tool_results)
        return f"(fake model) I read {len(tool_results)} document(s): {shown}"
    return f"(fake model) You said: {users[-1] if users else ''}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self.send_json(200, {"object": "list", "data": [
                {"id": "fake-model", "object": "model", "created": 0, "owned_by": "examples"}]})
        else:
            self.send_json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": {"message": "invalid JSON"}})
            return
        model = req.get("model", "fake-model")
        path = self.path.rstrip("/")
        if path.endswith("/chat/completions"):
            text = answer(req.get("messages") or [])
        elif path.endswith("/completions"):
            text = f"(fake model) You said: {text_of(req.get('prompt'))}"
            self.send_json(200, {"id": "cmpl-fake", "object": "text_completion", "created": int(time.time()),
                                 "model": model, "choices": [{"index": 0, "text": text, "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
            return
        else:
            self.send_json(404, {"error": {"message": "not found"}})
            return

        created = int(time.time())
        usage = {"prompt_tokens": 10, "completion_tokens": len(text.split()), "total_tokens": 10 + len(text.split())}
        if not req.get("stream"):
            self.send_json(200, {"id": "chatcmpl-fake", "object": "chat.completion", "created": created,
                                 "model": model, "usage": usage,
                                 "choices": [{"index": 0, "finish_reason": "stop",
                                              "message": {"role": "assistant", "content": text}}]})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def event(delta, finish=None, with_usage=False):
            chunk = {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "created": created, "model": model,
                     "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            if with_usage:
                chunk["usage"] = usage
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.flush()

        event({"role": "assistant", "content": ""})
        words = text.split(" ")
        for i, word in enumerate(words):
            event({"content": word + (" " if i < len(words) - 1 else "")})
        event({}, "stop", with_usage=True)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18199)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"fake upstream on http://{args.host}:{args.port}/v1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
