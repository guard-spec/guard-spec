#!/usr/bin/env python3
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Medians of the GPU timing runs (bench/gpu/colab_gpu_bench.sh).

    python3 bench/gpu/summarize_timing.py OUT_DIR > timing_summary.json

Reads OUT_DIR/timing-b<batch>-r<run>.json (cmd/benchlong reports) and writes,
per batch size, the median over the runs of: ms per window, windows/s and
tokens/s of the classifier path ("l2": every 256-token window of a document,
INFERENCE_BATCH_SIZE windows per run), the wall time of each document on that
path and on the gateway's fused chunk path (l1,l2, one chunk at a time), and
the score pass (all documents, one at a time).
"""

import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def med(xs):
    return statistics.median(xs) if xs else None


def main():
    out = Path(sys.argv[1])
    runs = defaultdict(list)
    for p in sorted(out.glob("timing-b*-r*.json")):
        m = re.match(r"timing-b(\d+)-r(\d+)\.json$", p.name)
        if m:
            runs[int(m.group(1))].append(json.loads(p.read_text()))
    res = {}
    for b, reps in sorted(runs.items()):
        l2 = defaultdict(list)
        doc = defaultdict(list)
        sp = defaultdict(list)
        for r in reps:
            sp["tokens_per_s"].append(r["score_pass"]["tokens_per_s"])
            sp["wall_s"].append(r["score_pass"]["wall_s"])
            for lat in r.get("latency") or []:
                path = lat["path"]
                if path == "l2":
                    for k in ("ms_per_window", "windows_per_s", "tokens_per_s"):
                        l2[k].append(lat[k])
                for d in lat["docs"]:
                    doc[(path, d["id"], d["tokens"])].append(d["wall_ms"])
        res[b] = dict(
            runs=len(reps),
            l2={k: med(v) for k, v in l2.items()},
            docs=[dict(path=p, id=i, tokens=t, wall_ms_median=med(v), wall_ms_runs=v)
                  for (p, i, t), v in sorted(doc.items())],
            score_pass={k: med(v) for k, v in sp.items()},
        )
    hdr = runs and next(iter(runs.values()))[0]["header"]
    json.dump(dict(header=hdr, by_batch=res), sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
