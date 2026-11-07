# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Checks the shape of the n8n workflow export without running n8n.

    python3 examples/n8n/validate.py [examples/n8n/guardspec-workflow.json]

It checks what n8n's import needs (name, nodes, connections; each node's id,
name, type, typeVersion, position and parameters; connections between nodes
that exist) and what the example promises: the requests go to the gateway's
/v1/chat/completions, a block (HTTP 400, content_filter) is handled rather
than failing the run, and no key or credential secret is in the file.
"""

import json
import re
import sys
from pathlib import Path

DEFAULT = Path(__file__).with_name("guardspec-workflow.json")
NODE_FIELDS = {"id": str, "name": str, "type": str, "typeVersion": (int, float), "position": list, "parameters": dict}
CONNECTION_TYPES = {"main", "ai_languageModel"}


def validate(path):
    errors = []
    raw = path.read_text(encoding="utf-8")
    wf = json.loads(raw)

    if re.search(r"gs_[0-9a-f]{8,}", raw):
        errors.append("the file contains something that looks like a Guard Spec key")
    if re.search(r"sk-[A-Za-z0-9]{8,}", raw):
        errors.append("the file contains something that looks like a provider key")

    for key, typ in (("name", str), ("nodes", list), ("connections", dict)):
        if not isinstance(wf.get(key), typ):
            errors.append(f"top level: {key} must be a {typ.__name__}")
    if errors:
        return errors

    names = set()
    ids = set()
    for i, node in enumerate(wf["nodes"]):
        where = f"nodes[{i}] ({node.get('name', '?')})"
        for field, typ in NODE_FIELDS.items():
            if not isinstance(node.get(field), typ):
                errors.append(f"{where}: {field} is missing or has the wrong type")
        if node.get("name") in names:
            errors.append(f"{where}: duplicate name")
        if node.get("id") in ids:
            errors.append(f"{where}: duplicate id")
        names.add(node.get("name"))
        ids.add(node.get("id"))
        pos = node.get("position")
        if isinstance(pos, list) and (len(pos) != 2 or not all(isinstance(v, (int, float)) for v in pos)):
            errors.append(f"{where}: position must be [x, y]")
        if not str(node.get("type", "")).startswith(("n8n-nodes-base.", "@n8n/n8n-nodes-langchain.")):
            errors.append(f"{where}: type {node.get('type')} is not a built-in n8n node")
        for cred_type, cred in (node.get("credentials") or {}).items():
            if set(cred) - {"id", "name"}:
                errors.append(f"{where}: credential {cred_type} carries more than an id and a name")

    for source, outputs in wf["connections"].items():
        if source not in names:
            errors.append(f"connections: unknown source node {source!r}")
        for conn_type, branches in outputs.items():
            if conn_type not in CONNECTION_TYPES:
                errors.append(f"connections[{source!r}]: unknown connection type {conn_type!r}")
            for branch in branches:
                for target in branch or []:
                    if target.get("node") not in names:
                        errors.append(f"connections[{source!r}]: unknown target node {target.get('node')!r}")
                    if target.get("type") != conn_type:
                        errors.append(f"connections[{source!r}]: target type {target.get('type')!r} != {conn_type!r}")

    connected = set(wf["connections"]) | {
        t["node"] for outs in wf["connections"].values() for bs in outs.values() for b in bs for t in (b or [])}
    for name in names - connected:
        errors.append(f"node {name!r} is not connected")

    http = [n for n in wf["nodes"] if n.get("type") == "n8n-nodes-base.httpRequest"]
    if not http:
        errors.append("no HTTP Request node")
    for n in http:
        p = n["parameters"]
        if "/v1/chat/completions" not in str(p.get("url", "")):
            errors.append(f"{n['name']}: url does not call /v1/chat/completions")
        if not p.get("options", {}).get("response", {}).get("response", {}).get("neverError"):
            errors.append(f"{n['name']}: a block (HTTP 400) would fail the run; set Never Error")
        if p.get("authentication") != "genericCredentialType" or p.get("genericAuthType") != "httpHeaderAuth":
            errors.append(f"{n['name']}: the key must come from a Header Auth credential")
    if not any(n.get("type") == "@n8n/n8n-nodes-langchain.lmChatOpenAi" for n in wf["nodes"]):
        errors.append("no OpenAI Chat Model node")
    return errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    errors = validate(path)
    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    if not errors:
        print(f"ok: {path}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
