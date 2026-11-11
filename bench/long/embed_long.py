# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Attack payloads embedded in long benign documents (RF-895d3533 R3).

The `full` profile puts each payload into a 2k-token host; the long document
rule of the long path (train/reports/r3_preregistration.md) depends on the
number of windows of a document, so its detection has to be measured on
documents of the size it acts on. This script takes the payloads of a built
`full` profile (its `control` documents: attack rows of the eval/ dev half,
bench split by payload id) and the benign documents of a built `long` profile
(100k and 200k tokens), and writes, for one bench split, every payload of that
split alone (`control`) and embedded in a long document of the same language
and split in the variants of the v6 gate G7:

  pos_start, pos_end, pos_random     at the start, the end, a random place;
  straddle_window                    across the end of a random 256-token window
                                     of the long path (254 content tokens, a new
                                     window every 190);
  straddle_chunk                     across the end of a random 2,048-byte chunk
                                     (a chunk every 1,792 bytes);
  straddle_segment                   across the end of a random 24 KiB segment
                                     (segments overlap by 1 KiB);
  split_adjacent                     cut in two halves with a sentence between them.

The host of each (payload, variant) is drawn with a seeded generator among the
long documents of the payload's language and split, so dev payloads only ever
sit in dev documents and holdout payloads in holdout documents. Documents the
gateway's sanitizer rejects are left out as hosts (--exclude-hosts).

    uv run --project bench --frozen python bench/long/embed_long.py \\
        --full $BENCH_CACHE/long/full/docs.jsonl --long $BENCH_CACHE/long/long/docs.jsonl \\
        --split dev --out <dir> [--exclude-hosts ids.txt]

Output: <dir>/docs.jsonl in the format of build.py (cmd/benchlong -corpus <dir>).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from tokenizers import Tokenizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import (  # noqa: E402
    CHUNK_BYTES, CHUNK_STEP, L2_CONTENT, L2_STEP, SEGMENT_BYTES,
    byte_to_char, find_tokenizer, insert, seeded, split_halves, token_char,
)

SEED = 20261111
VARIANTS = ["pos_start", "pos_end", "pos_random", "straddle_window", "straddle_chunk", "straddle_segment",
            "split_adjacent"]
SEGMENT_OVERLAP = 1 << 10


def embed(v: str, payload: str, lang: str, host: str, tok, rng) -> tuple[str, list[tuple[int, int]]]:
    if v == "pos_start":
        text, span = insert(host, 0, payload + "\n\n", sep="")
        return text, [(span[0], span[1] - 2)]
    if v == "pos_end":
        b0 = len((host + "\n\n").encode("utf-8"))
        return host + "\n\n" + payload, [(b0, b0 + len(payload.encode("utf-8")))]
    if v == "pos_random":
        text, span = insert(host, rng.randrange(len(host)), payload)
        return text, [span]
    if v == "straddle_window":
        enc = tok.encode(host)
        n = len(tok.encode(payload).ids)
        windows = max(1, (len(enc.ids) - L2_CONTENT) // L2_STEP)
        k = rng.randrange(windows) * L2_STEP + L2_CONTENT - n // 2  # centred on the end of a window
        text, span = insert(host, token_char(enc, k), payload)
        return text, [span]
    if v == "straddle_chunk":
        hb = len(host.encode("utf-8"))
        pb = len(payload.encode("utf-8"))
        c = rng.randrange(max(1, (hb - CHUNK_BYTES) // CHUNK_STEP))
        text, span = insert(host, byte_to_char(host, c * CHUNK_STEP + CHUNK_BYTES - pb // 2), payload)
        return text, [span]
    if v == "straddle_segment":
        hb = len(host.encode("utf-8"))
        pb = len(payload.encode("utf-8"))
        step = SEGMENT_BYTES - SEGMENT_OVERLAP
        j = rng.randrange(max(1, (hb - SEGMENT_BYTES) // step))
        text, span = insert(host, byte_to_char(host, j * step + SEGMENT_BYTES - pb // 2), payload)
        return text, [span]
    if v == "split_adjacent":
        a, b = split_halves(payload)
        bridge = "Số liệu đã được cập nhật tuần trước." if lang == "vi" else "The figures were updated last week."
        text, span = insert(host, rng.randrange(len(host)), f"{a} {bridge} {b}")
        return text, [span]
    raise ValueError(v)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--full", required=True, help="docs.jsonl of the full profile (its control documents are the payloads)")
    ap.add_argument("--long", required=True, help="docs.jsonl of the long profile (the hosts)")
    ap.add_argument("--split", required=True, choices=["dev", "holdout"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--exclude-hosts", help="file of host ids to leave out (one per line)")
    ap.add_argument("--tokenizer")
    args = ap.parse_args()

    tok = Tokenizer.from_file(str(find_tokenizer(args.tokenizer)))
    tok.no_truncation()
    tok.no_padding()
    exclude = set()
    if args.exclude_hosts:
        exclude = {ln.strip() for ln in Path(args.exclude_hosts).read_text("utf-8").splitlines() if ln.strip()}

    payloads = []
    with open(args.full, encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            if d["kind"] == "control" and d["split"] == args.split:
                payloads.append(d)
    hosts: dict[str, list[dict]] = {}
    with open(args.long, encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            if d["kind"] == "benign" and d["split"] == args.split and d["id"] not in exclude:
                hosts.setdefault(d["lang"], []).append(d)
    for lst in hosts.values():
        lst.sort(key=lambda d: d["id"])

    docs = []
    for p in sorted(payloads, key=lambda d: d["payload_id"]):
        meta = {k: p[k] for k in ("payload_id", "category", "source", "license")}
        docs.append({**p})
        for v in VARIANTS:
            rng = seeded(SEED, p["payload_id"], v)
            host = rng.choice(hosts[p["lang"]])
            text, spans = embed(v, p["text"], p["lang"], host["text"], tok, rng)
            docs.append({"id": f"long-attack-{p['payload_id']}-{v}", "kind": "attack", "lang": p["lang"],
                         "genre": host["genre"], "text": text, "variant": v, "host": host["id"],
                         "spans": [list(s) for s in spans], "split": args.split, "host_tokens": host["tokens"], **meta})
    for d in docs:
        d["tokens"] = len(tok.encode(d["text"]).ids)
        d["bytes"] = len(d["text"].encode("utf-8"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for d in docs)
    (out / "docs.jsonl").write_text(body, "utf-8")
    print(f"wrote {out / 'docs.jsonl'}: {len(docs)} documents ({len(payloads)} payloads), "
          f"{sum(d['tokens'] for d in docs):,} tokens, sha256 {hashlib.sha256(body.encode()).hexdigest()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
