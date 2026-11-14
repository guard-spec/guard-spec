# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""A sample organization API to put Guard Spec in front of (a custom backend).

It serves POST /search: {"query": "...", "filters": ["..."]} and answers with
results whose snippet carries an e-mail address, so the gateway's output
guard has something to redact. It counts the requests it gets and keeps the
last body as it arrived, for the demo to check what reached it:

    GET /_stats  ->  {"hits": 3, "last_body": "..."}

/_stats is the demo's own window into the backend; the gateway only forwards
the path prefixes its configuration allows (/search here). Standard library
only:

    python3 examples/custom-backend/sample_backend.py --port 18198
"""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

lock = threading.Lock()
stats = {"hits": 0, "last_body": ""}


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
        if self.path == "/_stats":
            with lock:
                self.send_json(200, dict(stats))
        else:
            self.send_json(404, {"detail": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        with lock:
            stats["hits"] += 1
            stats["last_body"] = raw.decode("utf-8", "replace")
        if self.path.split("?")[0] != "/search":
            self.send_json(404, {"detail": "not found"})
            return
        try:
            query = json.loads(raw).get("query", "")
        except (ValueError, AttributeError):
            self.send_json(400, {"detail": "invalid JSON"})
            return
        self.send_json(200, {
            "query": query,
            "results": [
                {"id": 42, "title": "Order help",
                 "snippet": f"For '{query}', write to support@shop.example or call the store."},
            ],
        })


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18198)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
