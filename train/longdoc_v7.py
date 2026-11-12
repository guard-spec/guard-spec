# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Long-document numbers of a classifier on the gateway's long path, for v7 (RF-895d3533 R6).

Implements the long-document part of train/reports/v7_preregistration.md: the R5 evaluation pipeline
(the `r5` rule set in internal/inference/rules, the long path of cmd/benchlong -long on, and the decisions
`base` and `strong75` of train/reports/r5_preregistration.md with n0 = 30, the R5 dev value, fixed), applied
to each model with that model's own calibration (the l1,l2 combiner and the cap for untrusted content of
its calibration.json). Reads the window dumps of cmd/benchlong (scores only, never text).

    uv run --frozen python longdoc_v7.py --stage dev --out <dir> \\
        --model ref=<model dir> --benign ref=<dump prefix> --attack ref=<dump prefix> ...
    uv run --frozen python longdoc_v7.py --stage holdout --out <dir> --model ... (long6, once)

A dump prefix P stands for P-dev.jsonl.gz and P-holdout.jsonl.gz (cmd/benchlong writes one file per bench
split); on long5 both are v7 dev, on long6 both are the v7 holdout. Writes <out>/v7_<stage>_longdoc.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import longdoc_r5 as L

N0 = 30                       # r5_dev.json fitted n0 (R5, v6 rules, long5 dev), fixed for v7
DECISIONS = ("strong75", "base")  # the evaluation decision first, today's decision next to it


def load_dump(prefix: str) -> list[dict]:
    docs = []
    for part in ("dev", "holdout"):
        p = Path(f"{prefix}-{part}.jsonl.gz")
        if p.exists():
            docs += L.load_full(str(p))
    if not docs:
        raise SystemExit(f"no dump {prefix}-dev.jsonl.gz / -holdout.jsonl.gz")
    return docs


def use_calibration(model_dir: str) -> dict:
    """Point longdoc_r5's long-path fusion at this model's calibration (combiner l1,l2 and the cap)."""
    cal = json.loads((Path(model_dir) / "calibration.json").read_text("utf-8"))
    lr = (cal.get("logreg") or {}).get("l1,l2")
    if lr is None or "W" not in lr:
        raise SystemExit(f"{model_dir}/calibration.json: no logreg l1,l2 combiner")
    cap = cal.get("l2_untrusted_max")
    if cap is None:
        raise SystemExit(f"{model_dir}/calibration.json: no l2_untrusted_max")
    L.LOGREG_L1L2 = {"W": [float(lr["W"][0]), float(lr["W"][1])], "B": float(lr["B"])}
    L.L2_CAP = float(cap)
    return {"logreg_l1l2": L.LOGREG_L1L2, "l2_untrusted_max": L.L2_CAP}


def pairs(values):
    return dict(v.split("=", 1) for v in values or [])


def summary(m: dict) -> dict:
    b, a = m["benign"], m["attack"]
    return {"blocked": b["all"]["k"], "docs": b["all"]["n"], "rate": b["all"]["rate"], "cp95": b["all"]["cp95"],
            "blocked_100k": b["both-100k"]["k"], "docs_100k": b["both-100k"]["n"], "cp95_100k": b["both-100k"]["cp95"],
            "blocked_200k": b["both-200k"]["k"], "docs_200k": b["both-200k"]["n"], "cp95_200k": b["both-200k"]["cp95"],
            "embedded": a["embedded"]["doc"]["rate"], "embedded_k": a["embedded"]["doc"]["k"], "embedded_n": a["embedded"]["doc"]["n"],
            "embedded_cp95": a["embedded"]["doc"]["cp95"],
            "alone": a["control"]["doc"]["rate"], "alone_k": a["control"]["doc"]["k"], "alone_n": a["control"]["doc"]["n"],
            "windows_blocking": m["benign_windows"]["blocking"], "windows": m["benign_windows"]["windows"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stage", choices=["dev", "holdout"], required=True)
    ap.add_argument("--model", action="append", required=True, help="<name>=<model dir with calibration.json>")
    ap.add_argument("--benign", action="append", required=True, help="<name>=<dump prefix>")
    ap.add_argument("--attack", action="append", required=True, help="<name>=<dump prefix>")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    models, bp, apx = pairs(a.model), pairs(a.benign), pairs(a.attack)
    if a.stage == "dev" and any("long6" in p for p in list(bp.values()) + list(apx.values())):
        raise SystemExit("the dev stage never reads long6")
    rep: dict = {"stage": a.stage, "n0": N0, "theta": L.THETA, "alpha": L.ALPHA, "decisions": list(DECISIONS), "models": {}}
    for name, mdir in models.items():
        cal = use_calibration(mdir)
        benign, attack = load_dump(bp[name]), load_dump(apx[name])
        res = {d: L.measure(d, N0, benign, attack) for d in DECISIONS}
        rep["models"][name] = {"model_dir": mdir, "calibration": cal, "results": res,
                               "summary": {d: summary(res[d]) for d in DECISIONS}}
        s = rep["models"][name]["summary"]["strong75"]
        print(f"{name}: strong75 blocked {s['blocked']}/{s['docs']} (100k {s['blocked_100k']}/{s['docs_100k']}, "
              f"200k {s['blocked_200k']}/{s['docs_200k']}), embedded {s['embedded']:.3f} vs alone {s['alone']:.3f}",
              file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"v7_{a.stage}_longdoc.json").write_text(json.dumps(rep, indent=1, default=float) + "\n", "utf-8")
    md = [f"# v7 long documents ({a.stage}), n0 {N0}\n"]
    for d in DECISIONS:
        md.append(f"\n## decision `{d}`\n\n" + L.md_results({n: rep["models"][n]["results"][d] for n in models}, list(models)))
    (out / f"v7_{a.stage}_longdoc.md").write_text("".join(md), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
