# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Long-document numbers of a classifier on the gateway's long path, for v8 (RF-3a9ce3f9 R7).

The pipeline of longdoc_v7.py unchanged (train/reports/v8_preregistration.md): the `r5` rule set, the long
path of cmd/benchlong -long on, the decisions `strong75` (evaluation) and `base` with n0 = 30, each model with
its own calibration. Reads the window dumps of cmd/benchlong (scores only, never text).

    uv run --frozen python longdoc_v8.py --stage dev --out <dir> \\
        --model ref=<model dir> --benign ref=<dump prefix> --attack ref=<dump prefix> ...
    uv run --frozen python longdoc_v8.py --stage holdout --out <dir> --model ... (long7, once)

On long5 (both halves) the dumps are v8 dev; on long7 they are the v8 holdout. The dev stage refuses a dump
path that names long6 (spent in R6) or long7 (the holdout); the holdout stage needs long7 paths.
Writes <out>/v8_<stage>_longdoc.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import longdoc_v7 as V7

N0 = V7.N0
DECISIONS = V7.DECISIONS
DEV_FORBIDDEN = ("long6", "long7")
HOLDOUT = "long7"


def check_paths(stage: str, paths) -> None:
    """Dev never reads long6 or long7; the holdout stage only reads long7 dumps."""
    paths = list(paths)
    if stage == "dev":
        bad = [p for p in paths if any(f in p for f in DEV_FORBIDDEN)]
        if bad:
            raise SystemExit(f"the dev stage never reads long6 or long7: {bad}")
    elif stage == "holdout":
        bad = [p for p in paths if HOLDOUT not in p]
        if bad:
            raise SystemExit(f"the holdout stage reads long7 dumps only: {bad}")
    else:
        raise SystemExit(f"unknown stage {stage}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stage", choices=["dev", "holdout"], required=True)
    ap.add_argument("--model", action="append", required=True, help="<name>=<model dir with calibration.json>")
    ap.add_argument("--benign", action="append", required=True, help="<name>=<dump prefix>")
    ap.add_argument("--attack", action="append", required=True, help="<name>=<dump prefix>")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    models, bp, apx = V7.pairs(a.model), V7.pairs(a.benign), V7.pairs(a.attack)
    check_paths(a.stage, list(bp.values()) + list(apx.values()))
    rep: dict = {"stage": a.stage, "n0": N0, "theta": V7.L.THETA, "alpha": V7.L.ALPHA, "decisions": list(DECISIONS),
                 "models": {}}
    for name, mdir in models.items():
        cal = V7.use_calibration(mdir)
        benign, attack = V7.load_dump(bp[name]), V7.load_dump(apx[name])
        res = {d: V7.L.measure(d, N0, benign, attack) for d in DECISIONS}
        rep["models"][name] = {"model_dir": mdir, "calibration": cal, "results": res,
                               "summary": {d: V7.summary(res[d]) for d in DECISIONS}}
        s = rep["models"][name]["summary"]["strong75"]
        print(f"{name}: strong75 blocked {s['blocked']}/{s['docs']} (100k {s['blocked_100k']}/{s['docs_100k']}, "
              f"200k {s['blocked_200k']}/{s['docs_200k']}), embedded {s['embedded']:.3f} vs alone {s['alone']:.3f}",
              file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"v8_{a.stage}_longdoc.json").write_text(json.dumps(rep, indent=1, default=float) + "\n", "utf-8")
    md = [f"# v8 long documents ({a.stage}), n0 {N0}\n"]
    for d in DECISIONS:
        md.append(f"\n## decision `{d}`\n\n" + V7.L.md_results({n: rep["models"][n]["results"][d] for n in models}, list(models)))
    (out / f"v8_{a.stage}_longdoc.md").write_text("".join(md), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
