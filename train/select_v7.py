# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Apply the pre-registered v7 selection rule (reports/v7_preregistration.md) and write reports/v7_dev.json.

    uv run --frozen python select_v7.py --arms B,C --ref ref --gates <gates dir> --longdoc <v7_dev_longdoc.json> \\
        [--runs <runs dir>] [--out reports/v7_dev.json]

Inputs (every number from ONNX INT8 on the laptop's CPU):

- <gates>/<name>/{eval,codelog,embedded,val_v3}.json and <gates>/<name>/benchlong-full.json for every arm and
  the GPU reference `ref` (cmd/eval -json, cmd/benchlong -json, as run_arms_v6.sh writes them);
  <gates>/v3b/{eval,codelog,embedded,val_v3}.json and <gates>/l1/embedded.json (the v6 gates' references).
- --longdoc: longdoc_v7.py's dev report (long5, both halves; the R5 embedded-attack documents).
- --runs <dir>/<name>/train_log.json: recorded only.

Gates: G1-G7 exactly as select_v6.py (v6's rule); G8 eval/data dev TPR at FPR <= 1% not below the lower end
of the two-sided 95% Clopper-Pearson interval of the reference's; LD-TPR embedded detection on long5 >=
detection alone - 0.05 (decision strong75); LD-REF blocked long5 benign documents (strong75) fewer than the
reference's. The target LD-FPR (at most 1% of the long5 documents blocked) is reported; it does not decide.

Never read here: eval/ hold-out slices, the bench/long hold-out rows of the full profile, long6.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import select_v6 as S6
from longdoc_r3 import clopper_pearson

ROOT = Path(__file__).resolve().parent
G8_SET = ("eval", "at_fpr_1pct", "tpr")
LD_DECISION = "strong75"
LD_ALPHA = 0.01
LD_TPR_MARGIN = 0.05


def gates_v7(name, reps, ld, ref="ref"):
    g = S6.gates_for(name, reps[name], reps)
    a = S6.dev(reps[name]["eval"], "at_fpr_1pct", "tpr")
    r = S6.dev(reps[ref]["eval"], "at_fpr_1pct", "tpr")
    n = int(reps[ref]["eval"]["slices"]["dev"].get("n_attack") or 0)
    lo = clopper_pearson(round(r * n), n)[0] if n else float("nan")
    g["G8"] = dict(ok=a >= lo - 1e-12, value=a, ref=r, ref_cp95_low=lo, n_attack=n,
                   what="eval/data dev TPR at FPR <= 1% not below the lower end of the reference's CP95 interval")
    s = ld["models"][name]["summary"][LD_DECISION]
    sr = ld["models"][ref]["summary"][LD_DECISION]
    g["LD-TPR"] = dict(ok=s["embedded"] >= s["alone"] - LD_TPR_MARGIN - 1e-12, value=s["embedded"], alone=s["alone"],
                       what="long5: detection of the embedded R5 documents (seven placements) >= the payloads alone - 0.05")
    g["LD-REF"] = dict(ok=s["blocked"] < sr["blocked"], value=s["blocked"], ref=sr["blocked"], docs=s["docs"],
                       what="long5: blocked benign 100k + 200k documents (r5 rules, strong75) fewer than the reference")
    return g


def target(ld, name):
    s = ld["models"][name]["summary"][LD_DECISION]
    return dict(met=s["blocked"] <= math.floor(LD_ALPHA * s["docs"]), blocked=s["blocked"], docs=s["docs"],
                cp95=s["cp95"], limit=math.floor(LD_ALPHA * s["docs"]))


def decide(arms, gates, ld):
    passing = [a for a in arms if all(x["ok"] for x in gates[a].values())]
    key = lambda a: (ld["models"][a]["summary"][LD_DECISION]["blocked"],  # noqa: E731
                     -ld["models"][a]["summary"][LD_DECISION]["embedded"],
                     -round(gates[a]["G1"]["value"], S6.G1_DECIMALS), arms.index(a))
    met = {a: sum(x["ok"] for x in gates[a].values()) for a in arms}
    if passing:
        c = sorted(passing, key=key)[0]
        return dict(status="chosen", chosen=c, order=sorted(passing, key=key), gates_met=met, target=target(ld, c))
    fb = sorted(arms, key=lambda a: (-met[a],) + key(a))[0]
    return dict(status="no arm qualifies", chosen=None, fallback_candidate=fb, gates_met=met, target=target(ld, fb),
                note="no v7; long6 is still scored once for the fallback candidate and the reference, for the record")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", required=True, help="comma-separated arm names, in the pre-registered order")
    ap.add_argument("--ref", default="ref")
    ap.add_argument("--gates", required=True)
    ap.add_argument("--longdoc", required=True)
    ap.add_argument("--runs")
    ap.add_argument("--out", default=str(ROOT / "reports" / "v7_dev.json"))
    a = ap.parse_args(argv)
    arms = a.arms.split(",")
    names = arms + [a.ref]
    reps, missing = S6.load_gates(Path(a.gates), names)
    if reps is None:
        raise SystemExit(f"missing reports: {missing}")
    ld = json.loads(Path(a.longdoc).read_text("utf-8"))
    gates = {n: gates_v7(n, reps, ld, a.ref) for n in names}
    rep = dict(rule="reports/v7_preregistration.md (pre-registered)", ref=a.ref, arms={})
    for n in names:
        rep["arms"][n] = dict(gates=gates[n], recorded=S6.recorded(reps[n], reps),
                              longdoc={d: ld["models"][n]["summary"][d] for d in ld["decisions"]}, target=target(ld, n))
        if a.runs and (Path(a.runs) / n / "train_log.json").exists():
            log = json.loads((Path(a.runs) / n / "train_log.json").read_text("utf-8"))
            rep["arms"][n]["train"] = dict(best_epoch=log.get("best_epoch"), train_minutes=round(log["train_seconds"] / 60, 1),
                                           n_train_rows=log.get("n_train_rows"), n_train_windows=log.get("n_train"),
                                           seed=log["config"].get("seed"), device=log.get("device"),
                                           val_loss=[round(e["val_loss"], 4) for e in log["epochs"]],
                                           oversample_kind=log["config"]["train"].get("oversample_kind"),
                                           train_files=[Path(p).name for p in log["config"]["data"].get("train_files", [])])
    for n in ld["models"]:
        if n not in names:
            rep.setdefault("also_measured", {})[n] = {d: ld["models"][n]["summary"][d] for d in ld["decisions"]}
    rep["decision"] = decide(arms, gates, ld)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2, ensure_ascii=False, default=float) + "\n", "utf-8")
    print(json.dumps(rep["decision"], indent=2, default=float))
    return rep


if __name__ == "__main__":
    main()
