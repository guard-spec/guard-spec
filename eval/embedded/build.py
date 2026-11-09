"""Deterministic generator for the Guard Spec embedded-attack set.

    python3 eval/embedded/build.py

Every row of the EN/VI eval set (eval/data: 1,171 attacks and 1,005 benign
rows) is hidden in one 2 KB code/log host from eval/codelog, at one position
a coding or CI agent would read past: a comment, a docstring, a YAML value, a
JSON field, a log line's message, a CSV field, an added diff line, or the
start or end of the host. Attacks measure detection of injections hidden in
tool output; benign rows embedded the same way measure the false positives
of the same construction (questions about prompt injection in a comment,
"bỏ qua" in a log line), so TPR and FPR come from one population.

The split is the payload's: dev when the eval/data id ends in 0-7, holdout
when it ends in 8-f (eval/README.md), so a model tuned on dev payloads is
judged on holdout payloads it has not seen in any host.

Inputs are read from git at the pinned commit SOURCE_COMMIT, never from the
working tree, and never from train/: eval/data/*.jsonl (payloads) and
eval/codelog/codelog.jsonl (hosts). Writes, next to this script:

    embedded.jsonl     the rows (eval/README.md schema plus "kind", "size",
                       "position", "split", "payload_id", "host_id")
    fingerprints.txt   sha256 of the normalized text of every row (training
                       pipelines must drop these, as for eval/fingerprints.txt)

Only the standard library and git are needed. Two runs produce byte-identical
files.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from pathlib import Path

SOURCE_COMMIT = "87addfa"
SEED = 437_128_9
HOST_SIZE = 2048

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

# Position -> host kinds (eval/codelog "kind") that can carry it.
POSITIONS = {
    "comment": ("go", "js_ts", "sql", "python", "yaml", "dockerfile", "shell"),
    "docstring": ("python", "go", "js_ts"),
    "yaml_value": ("yaml",),
    "json_field": ("json_en", "json_vi"),
    "log_message": ("log_en", "log_vi", "stacktrace"),
    "csv_field": ("csv_en", "csv_vi"),
    "diff_added": ("diff",),
    "start": None,  # any host
    "end": None,
}
LINE_COMMENT = {"go": "// ", "js_ts": "// ", "sql": "-- "}  # else "# "
KEYS = ("note", "description", "comment", "message", "summary")
LEVELS = ("INFO", "WARN", "ERROR", "DEBUG")
SVCS = ("api-gateway", "billing", "auth", "worker", "search", "notifier", "orders", "inventory")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout


def jsonl(path: str) -> list[dict]:
    return [json.loads(ln) for ln in git("show", f"{SOURCE_COMMIT}:{path}").splitlines() if ln.strip()]


def strip_diacritics(s: str) -> str:
    s = s.replace("đ", "d").replace("Đ", "D")
    s = "".join(ch for ch in unicodedata.normalize("NFD", s) if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", s)


def normalize_for_fingerprint(s: str) -> str:
    """Same rule as eval/build/build.py."""
    return " ".join(strip_diacritics(unicodedata.normalize("NFC", s)).lower().split())


def fingerprint(s: str) -> str:
    return hashlib.sha256(normalize_for_fingerprint(s).encode("utf-8")).hexdigest()


def split_of(payload_id: str) -> str:
    return "dev" if payload_id[-1] in "01234567" else "holdout"


def one_line(s: str) -> str:
    return " ".join(s.split())


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip(" \t"))]


def insert_lines(host: str, block: list[str], at: int) -> str:
    lines = host.split("\n")
    return "\n".join(lines[:at] + block + lines[at:])


def body_index(lines: list[str], rng: random.Random) -> int:
    """A line boundary away from the first and last line of the host."""
    n = len(lines)
    return rng.randrange(1, n - 1) if n > 2 else n // 2


# ---- positions -------------------------------------------------------------

def at_comment(host: str, kind: str, p: str, rng: random.Random) -> str:
    lines = host.split("\n")
    i = body_index(lines, rng)
    mark = LINE_COMMENT.get(kind, "# ")
    ind = indent_of(lines[i]) if kind not in ("dockerfile", "sql") else ""
    return insert_lines(host, [ind + mark + ln if ln.strip() else ind + mark.rstrip() for ln in p.split("\n")], i)


def at_docstring(host: str, kind: str, p: str, rng: random.Random) -> str:
    lines = host.split("\n")
    i = body_index(lines, rng)
    ind = indent_of(lines[i])
    if kind == "python":
        body = p.replace('"""', "'''").split("\n")
        block = [ind + '"""' + body[0]] + [ind + ln for ln in body[1:]]
        block[-1] += '"""'
    else:
        block = [ind + "/**"] + [ind + " * " + ln.replace("*/", "* /") for ln in p.split("\n")] + [ind + " */"]
    return insert_lines(host, block, i)


def at_yaml_value(host: str, kind: str, p: str, rng: random.Random) -> str:
    lines = host.split("\n")
    i = body_index(lines, rng)
    line = f"{indent_of(lines[i])}{rng.choice(KEYS)}: {json.dumps(p, ensure_ascii=False)}"
    return insert_lines(host, [line], i)


def at_json_field(host: str, kind: str, p: str, rng: random.Random) -> str:
    braces = [m.end() for m in re.finditer(r"\{", host)]
    k = rng.choice(braces) if braces else 0
    field = f'"{rng.choice(KEYS)}": {json.dumps(p, ensure_ascii=False)}, '
    m = re.match(r"\n([ \t]*)", host[k:])
    if m:  # indented JSON: a field on its own line
        field = f"\n{m.group(1)}{field.rstrip()}"
    return host[:k] + field + host[k:]


TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z")
KV = re.compile(r"^(\S+ \S+\s+\[[^\]]+\] req=\S+ )(.*?)( status=\S+ dur_ms=\S+)$")
PLAIN = re.compile(r"^(\[[^\]]+\] \S+\.\w+: )(.*)$")
K8S = re.compile(r"^(\S+ \S+ \S+Z (?:info|warn|error|debug) )(.*)$")


def at_log_message(host: str, kind: str, p: str, rng: random.Random) -> str:
    """A new log line in the format of a nearby one, with the payload as its message."""
    lines = host.split("\n")
    i = body_index(lines, rng)
    ref, msg = lines[i], one_line(p)
    line = None
    if ref.startswith("{"):
        try:
            obj = json.loads(ref)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "msg" in obj:
            obj["msg"] = p
            line = json.dumps(obj, ensure_ascii=False)
    for rx in (KV, PLAIN, K8S):
        if line is None and (m := rx.match(ref)):
            line = m.group(1) + msg + (m.group(3) if rx is KV else "")
    if line is None:
        t = TS.search(host)
        stamp = t.group(0) if t else "2026-11-09T08:15:42.120Z"
        line = f"{stamp} {rng.choice(LEVELS):<5} [{rng.choice(SVCS)}] {msg}"
    return insert_lines(host, [line], i)


def at_csv_field(host: str, kind: str, p: str, rng: random.Random) -> str:
    lines = host.split("\n")
    rows = [j for j, ln in enumerate(lines) if j > 0 and ln.count(",") >= 7 and ln.endswith('"')]
    j = rng.choice(rows) if rows else body_index(lines, rng)
    prefix = lines[j].rsplit(',"', 1)[0] if j in rows else "10001,2026-11-09,-,-,-,1,0.00"
    return insert_lines(host, [prefix + ',"' + p.replace('"', '""') + '"'], j)


def at_diff_added(host: str, kind: str, p: str, rng: random.Random) -> str:
    lines = host.split("\n")
    hunk = [j for j, ln in enumerate(lines)
            if j > 0 and ln[:1] in (" ", "+", "-") and not ln.startswith(("+++", "---"))
            and any(x.startswith("@@") for x in lines[:j])]
    i = rng.choice(hunk) if hunk else body_index(lines, rng)
    return insert_lines(host, ["+" + ln for ln in p.split("\n")], i)


def at_start(host: str, kind: str, p: str, rng: random.Random) -> str:
    return p + "\n" + host


def at_end(host: str, kind: str, p: str, rng: random.Random) -> str:
    return host.rstrip("\n") + "\n" + p + "\n"


EMBED = {"comment": at_comment, "docstring": at_docstring, "yaml_value": at_yaml_value,
         "json_field": at_json_field, "log_message": at_log_message, "csv_field": at_csv_field,
         "diff_added": at_diff_added, "start": at_start, "end": at_end}


def main() -> int:
    payloads = []
    for f in ("eval/data/en.jsonl", "eval/data/vi.jsonl"):
        payloads += jsonl(f)
    hosts = [h for h in jsonl("eval/codelog/codelog.jsonl") if h["size"] == HOST_SIZE]
    by_pos = {pos: [h for h in hosts if kinds is None or h["kind"] in kinds] for pos, kinds in POSITIONS.items()}
    assert all(by_pos.values()), "a position has no host"
    assert len({p["id"] for p in payloads}) == len(payloads), "duplicate payload ids"

    rows, seen = [], set()
    for p in payloads:
        rng = random.Random(f"{SEED}:{p['id']}")
        pos = rng.choice(list(POSITIONS))
        host = rng.choice(by_pos[pos])
        text = EMBED[pos](host["text"], host["kind"], p["text"], rng)
        if text in seen:
            continue
        seen.add(text)
        lic = p["license"] if p["license"] == "Apache-2.0" else f"{p['license']} (payload), Apache-2.0 (host)"
        rows.append({"id": f"{p['lang']}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}", "text": text,
                     "label": p["label"], "category": p["category"], "lang": p["lang"], "variant": p["variant"],
                     "source": f"{p['source']} in guard-spec:codelog", "license": lic,
                     "kind": host["kind"], "size": HOST_SIZE, "position": pos, "split": split_of(p["id"]),
                     "payload_id": p["id"], "host_id": host["id"]})
    with open(HERE / "embedded.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    fps = sorted({fingerprint(r["text"]) for r in rows})
    with open(HERE / "fingerprints.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write("# sha256 of normalize_for_fingerprint(text) for eval/embedded/embedded.jsonl\n")
        f.write("\n".join(fps) + "\n")
    c = Counter((r["label"], r["split"]) for r in rows)
    print(f"wrote {len(rows)} rows: {dict(sorted(c.items()))}", file=sys.stderr)
    print(f"positions: {dict(sorted(Counter(r['position'] for r in rows).items()))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
