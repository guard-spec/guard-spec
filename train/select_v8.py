# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Apply the pre-registered v8 selection rule (reports/v8_preregistration.md) and write reports/v8_dev.json.

    uv run --frozen python select_v8.py --arms D,E --ref ref --gates <gates dir> --longdoc <v8_dev_longdoc.json> \\
        [--runs <runs dir>] [--out reports/v8_dev.json]

The gates are R6's unchanged (select_v7.gates_v7): G1-G7 as select_v6.py, G8 eval/data dev TPR at FPR <= 1%
not below the lower end of the reference's two-sided CP95 interval, LD-TPR long5 embedded detection >= alone
- 0.05 (strong75), LD-REF fewer blocked long5 benign documents (strong75) than the reference. LD-FPR (at most
1% of the long5 documents blocked) is reported; it does not decide.

Among the arms passing every gate: fewest blocked long5 documents (strong75), then higher long5 embedded
detection, then higher G1 (four decimals), then the order D, E. No arm passing: the arm meeting most gates
(same keys) is the fallback candidate; long7 is still scored once for it, for the record.

Inputs as select_v7.py. Never read here: eval/ hold-out slices, the bench/long full hold-out rows, long6, long7.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import select_v6 as S6
import select_v7 as S7

ROOT = Path(__file__).resolve().parent
LD_DECISION = S7.LD_DECISION
gates_v8 = S7.gates_v7
target = S7.target


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
                note="no v8; long7 is still scored once for the fallback candidate, the reference and the released "
                     "v6, for the record")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", required=True, help="comma-separated arm names, in the pre-registered order (D,E)")
    ap.add_argument("--ref", default="ref")
    ap.add_argument("--gates", required=True)
    ap.add_argument("--longdoc", required=True)
    ap.add_argument("--runs")
    ap.add_argument("--out", default=str(ROOT / "reports" / "v8_dev.json"))
    a = ap.parse_args(argv)
    arms = a.arms.split(",")
    names = arms + [a.ref]
    ld = json.loads(Path(a.longdoc).read_text("utf-8"))
    if ld.get("stage") != "dev":
        raise SystemExit(f"{a.longdoc}: not a dev-stage report (stage {ld.get('stage')!r})")
    reps, missing = S6.load_gates(Path(a.gates), names)
    if reps is None:
        raise SystemExit(f"missing reports: {missing}")
    gates = {n: gates_v8(n, reps, ld, a.ref) for n in names}
    rep = dict(rule="reports/v8_preregistration.md (pre-registered)", ref=a.ref, arms={})
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
