#!/usr/bin/env python3
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Compare two runs of the same rows: score differences and decision agreement.

    python3 bench/gpu/compare_scores.py A B [--threshold 0.85] [--json out.json]

A and B are both `cmd/eval -scores` files (one JSON object per row: id,
score, blocked) or both `cmd/benchlong -units` files (one object per
document: id, units {layer: [score per unit]}). Rows and units are matched by
id (and unit position). Used for:

- FP16 vs INT8 on the CPU (RF-b74de2b9 G2, train/reports/fp16_agreement_*.md):
  how often the block decision at 0.85 is the same;
- CUDA vs CPU on the same FP16 file (G4): the largest absolute score
  difference (target <= 1e-3) and identical decisions.

Only scores are read; no text is in either file.
"""

from __future__ import annotations

import argparse
import json
import sys


def load(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                rows[r["id"]] = r
    return rows


def pairs(a, b):
    """(key, score_a, score_b, blocked_a, blocked_b) for every matched row or unit."""
    ids = sorted(set(a) & set(b))
    for i in ids:
        ra, rb = a[i], b[i]
        if "units" in ra:
            for layer in sorted(set(ra["units"]) & set(rb["units"])):
                ua, ub = ra["units"][layer] or [], rb["units"][layer] or []
                if len(ua) != len(ub):
                    raise SystemExit(f"{i} {layer}: {len(ua)} vs {len(ub)} units")
                for k, (x, y) in enumerate(zip(ua, ub)):
                    yield (layer, f"{i}#{k}"), x, y, None, None
        else:
            yield ("row", i), ra["score"], rb["score"], ra.get("blocked"), rb.get("blocked")


def compare(a, b, thr):
    groups = {}
    for (group, key), x, y, ba, bb in pairs(a, b):
        g = groups.setdefault(group, dict(n=0, max_abs=0.0, sum_abs=0.0, agree=0, flips=[],
                                          blocked_n=0, blocked_agree=0, a_pos=0, b_pos=0))
        d = abs(x - y)
        g["n"] += 1
        g["sum_abs"] += d
        if d > g["max_abs"]:
            g["max_abs"], g["max_key"] = d, key
        da, db = x >= thr, y >= thr
        g["a_pos"] += da
        g["b_pos"] += db
        if da == db:
            g["agree"] += 1
        else:
            g["flips"].append(dict(key=key, a=round(x, 4), b=round(y, 4)))
        if ba is not None and bb is not None:
            g["blocked_n"] += 1
            g["blocked_agree"] += ba == bb
    out = {}
    for group, g in groups.items():
        r = dict(n=g["n"], max_abs=g["max_abs"], max_key=g.get("max_key"), mean_abs=g["sum_abs"] / max(1, g["n"]),
                 decisions_at=thr, agreement=g["agree"] / max(1, g["n"]), disagreements=len(g["flips"]),
                 a_at_or_above=g["a_pos"], b_at_or_above=g["b_pos"], flips=g["flips"][:50])
        if g["blocked_n"]:
            r["gateway_blocked_agreement"] = g["blocked_agree"] / g["blocked_n"]
        out[group] = r
    return dict(only_in_a=len(set(a) - set(b)), only_in_b=len(set(b) - set(a)), groups=out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--threshold", type=float, default=0.85)
    ap.add_argument("--json", help="also write the result here")
    args = ap.parse_args()
    res = compare(load(args.a), load(args.b), args.threshold)
    for group, r in sorted(res["groups"].items()):
        extra = f", gateway decision agreement {r['gateway_blocked_agreement']:.4%}" if "gateway_blocked_agreement" in r else ""
        print(f"{group}: n={r['n']} max|d|={r['max_abs']:.2e} mean|d|={r['mean_abs']:.2e} "
              f"agreement@{r['decisions_at']}={r['agreement']:.4%} ({r['disagreements']} differ){extra}")
    if res["only_in_a"] or res["only_in_b"]:
        print(f"unmatched: {res['only_in_a']} only in A, {res['only_in_b']} only in B", file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
