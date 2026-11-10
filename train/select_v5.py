"""Apply the pre-registered v5 arm-selection rule (MODEL_CARD.md, "v5", "Decision rule") and write
reports/train_arms_v5.json.

    uv run --frozen python select_v5.py --arm A=runs/v5-A --arm B=runs/v5-B --arm C=runs/v5-C \
        [--gates runs/v5-gates] [--out reports/train_arms_v5.json]

Inputs, all produced by run_arms_v5.sh:

- <run>/train_log.json and <run>/val_scores.jsonl of every arm (train.py): text-level validation
  scores of the best epoch, worst window per row, risk = 1 - p(benign), PyTorch FP32, L2 alone.
- --gates <dir>: cmd/eval -json reports on the dev slices of eval/ (direct path), eval/codelog and
  eval/embedded (tool path, code corroboration off), as <dir>/<arm>/{eval,codelog,embedded}.json for
  every arm and for v3b, and <dir>/l1/embedded.json (L1 only). Without --gates (or with reports
  missing) the gates are reported as pending and no arm is chosen.

Never read: val_v5_holdout, the hold-out slices of eval/ (only `slices.dev` is used), owner hold-outs.
Standard library only (the tests run it without the training environment).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORIGINAL_VAL = ["val", "val_hard", "val_vi_variants", "val_v3", "val_v4"]  # the v4 validation files
VAL_V5 = "val_v5"  # set B of the v5 builder (v5_val, set A's validation split, is for early stopping only)

# Thresholds of the rule (MODEL_CARD.md, v5). Changing one changes the pre-registered rule.
TARGET_FPR = 0.01            # risk threshold of an arm: benign FPR <= 1% on the original validation
Q1_TPR_MARGIN = 0.01         # original validation TPR at FPR <= 1% within 0.01 of the best arm
Q1_AUC_MARGIN = 0.002        # original validation AUC within 0.002 of the best arm
RANK_TIE = 0.005             # val_v5 (TPR - FPR) differences below this are ties
G2_MAX_FPR = 0.03            # eval/codelog dev FPR at 0.85, corroboration off


# ---------------------------------------------------------------------------- metrics (stdlib)

def threshold_at_fpr(neg, target):
    """Smallest threshold t with mean(neg >= t) <= target (common_train.threshold_at_fpr, float64)."""
    neg = sorted(neg, reverse=True)
    k = int(math.floor(target * len(neg)))
    if k >= len(neg):
        return float(neg[-1])
    if k > 0 and neg[k - 1] > neg[k]:
        return (neg[k - 1] + neg[k]) / 2
    return math.nextafter(neg[k], math.inf)


def rate(scores, t):
    return sum(s >= t for s in scores) / len(scores) if scores else float("nan")


def auc(pos, neg):
    """ROC AUC (Mann-Whitney, ties count half)."""
    if not pos or not neg:
        return float("nan")
    allv = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    rank_sum, i = 0.0, 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        r = (i + 1 + j) / 2  # mean 1-based rank of the tie group
        rank_sum += r * sum(1 for x in allv[i:j] if x[1] == 1)
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def validation_metrics(scores):
    """scores: rows of val_scores.jsonl. Original validation threshold, then val_v5 at that threshold."""
    def split(rows):
        pos = [r["risk"] for r in rows if r["labels"] != ["benign"]]
        neg = [r["risk"] for r in rows if r["labels"] == ["benign"]]
        return pos, neg

    orig = [r for r in scores if r["file"] in ORIGINAL_VAL]
    v5 = [r for r in scores if r["file"] == VAL_V5]
    if not orig or not v5:
        raise SystemExit("val_scores.jsonl needs the original validation files and val_v5 (train.py --v5-dir)")
    op, on = split(orig)
    vp, vn = split(v5)
    t = threshold_at_fpr(on, TARGET_FPR)
    m = dict(threshold=t,
             orig=dict(n_attack=len(op), n_benign=len(on), auc=auc(op, on), tpr=rate(op, t), fpr=rate(on, t)),
             val_v5=dict(n_attack=len(vp), n_benign=len(vn), auc=auc(vp, vn), tpr=rate(vp, t), fpr=rate(vn, t)))
    m["val_v5"]["tpr_minus_fpr"] = m["val_v5"]["tpr"] - m["val_v5"]["fpr"]
    by_pos = {}
    for r in v5:
        if r["labels"] != ["benign"] and r.get("position"):
            by_pos.setdefault(r["position"], []).append(r["risk"])
    m["val_v5"]["tpr_by_position"] = {k: rate(v, t) for k, v in sorted(by_pos.items())}
    by_kind = {}
    for r in v5:
        if r["labels"] == ["benign"]:
            by_kind.setdefault(r.get("kind") or "?", []).append(r["risk"])
    m["val_v5"]["fpr_by_kind"] = {k: rate(v, t) for k, v in sorted(by_kind.items())}
    return m


# ---------------------------------------------------------------------------- the rule

def rank_arms(val):
    """Q1 and the validation ranking. val: {arm: validation_metrics}. Returns (order, q1 per arm)."""
    best_tpr = max(v["orig"]["tpr"] for v in val.values())
    best_auc = max(v["orig"]["auc"] for v in val.values())
    q1 = {a: v["orig"]["tpr"] >= best_tpr - Q1_TPR_MARGIN - 1e-12 and v["orig"]["auc"] >= best_auc - Q1_AUC_MARGIN - 1e-12
          for a, v in val.items()}

    def key(a):
        v = val[a]
        # Ties within RANK_TIE: quantize the primary key so near-equal arms fall to the next keys.
        return (not q1[a], -math.floor(v["val_v5"]["tpr_minus_fpr"] / RANK_TIE + 1e-9), -v["orig"]["tpr"],
                v.get("val_loss", math.inf), a)

    return sorted(val, key=key), q1


def dev(report, metric, field):
    """slices.dev.<metric>.<field> of a cmd/eval -json report."""
    try:
        return report["slices"]["dev"][metric][field]
    except (KeyError, TypeError):
        raise SystemExit("cmd/eval report without slices.dev: run it with the dev/holdout slices (RF-437128e9 T1)")


def gates_for(arm, rep, ref):
    """G1-G4 of one arm. rep: {eval, codelog, embedded} reports of the arm; ref: v3b's and L1's."""
    g = {}
    a, b = dev(rep["eval"], "at_fpr_1pct", "tpr"), dev(ref["v3b"]["eval"], "at_fpr_1pct", "tpr")
    g["G1"] = dict(ok=a >= b, value=a, v3b=b, what="eval/ dev TPR at FPR <= 1% (fused, direct path) >= v3b")
    a = dev(rep["codelog"], "at_0.85", "fpr")
    g["G2"] = dict(ok=a <= G2_MAX_FPR, value=a, limit=G2_MAX_FPR,
                   what="eval/codelog dev FPR at 0.85 (tool path, corroboration off) <= 0.03")
    a = dev(rep["embedded"], "at_0.85", "tpr")
    b, c = dev(ref["v3b"]["embedded"], "at_0.85", "tpr"), dev(ref["l1"]["embedded"], "at_0.85", "tpr")
    g["G3"] = dict(ok=a >= b and a >= c, value=a, v3b=b, l1=c,
                   what="eval/embedded dev TPR at 0.85 (tool path, corroboration off) >= v3b and >= L1 alone")
    # G4 (amendment of 2026-11-10, before any arm is chosen): G3's TPR is only meaningful if the arm does not
    # buy it by blocking more of the benign twins of the same set.
    a, b = dev(rep["embedded"], "at_0.85", "fpr"), dev(ref["v3b"]["embedded"], "at_0.85", "fpr")
    g["G4"] = dict(ok=a <= b, value=a, v3b=b,
                   what="eval/embedded dev FPR at 0.85 (tool path, corroboration off) <= v3b")
    return g


def decide(order, q1, gates):
    """The first arm in validation order that meets Q1 and G1-G4. gates: {arm: gates_for(...)} or None."""
    if gates is None:
        return dict(status="gates pending", chosen=None, validation_order=order,
                    note="validation ranking only; run the gates (run_arms_v5.sh gates) before choosing")
    for a in order:
        if q1[a] and all(x["ok"] for x in gates[a].values()):
            return dict(status="chosen", chosen=a, validation_order=order)
    met = {a: int(q1[a]) + sum(x["ok"] for x in gates[a].values()) for a in order}
    shadow = max(order, key=lambda a: (met[a], -order.index(a)))
    return dict(status="no arm qualifies", chosen=None, shadow_candidate=shadow, rules_met=met, validation_order=order,
                note="v5 is not recommended; the arm meeting most of Q1, G1-G4 (tie: validation order) is reported "
                     "as a shadow-mode candidate only")


# ---------------------------------------------------------------------------- main

def read_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f]


def load_gates(gdir: Path, arms):
    names = list(arms) + ["v3b"]
    need = [gdir / n / f"{s}.json" for n in names for s in ("eval", "codelog", "embedded")] + [gdir / "l1" / "embedded.json"]
    missing = [str(p) for p in need if not p.exists()]
    if missing:
        return None, missing
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))  # noqa: E731
    reps = {n: {s: load(gdir / n / f"{s}.json") for s in ("eval", "codelog", "embedded")} for n in names}
    reps["l1"] = {"embedded": load(gdir / "l1" / "embedded.json")}
    return reps, []


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", required=True, metavar="NAME=RUN_DIR")
    ap.add_argument("--gates", help="directory with the cmd/eval reports (see the module docstring)")
    ap.add_argument("--out", default=str(ROOT / "reports" / "train_arms_v5.json"))
    a = ap.parse_args(argv)
    arms = dict(s.split("=", 1) for s in a.arm)
    report = dict(rule="MODEL_CARD.md, v5, Decision rule (pre-registered)", arms={})
    val = {}
    for name, run in arms.items():
        run = Path(run) if Path(run).is_absolute() else ROOT / run
        log = json.loads((run / "train_log.json").read_text(encoding="utf-8"))
        ep = {e["epoch"]: e for e in log["epochs"]}
        m = validation_metrics(read_jsonl(run / "val_scores.jsonl"))
        m["val_loss"] = ep[log["best_epoch"]]["val_loss"]
        val[name] = m
        report["arms"][name] = dict(
            n_train_rows_per_epoch=log.get("n_train_rows"), n_train_windows_per_epoch=log.get("n_train"),
            n_val_windows=log.get("n_val"), best_epoch=log["best_epoch"],
            train_minutes=round(log["train_seconds"] / 60, 1),
            val_loss=[round(e["val_loss"], 4) for e in log["epochs"]],
            oversample=log["config"]["train"].get("oversample"), oversample_kind=log["config"]["train"].get("oversample_kind"),
            train_files=[Path(p).name for p in log["config"]["data"].get("train_files", [])],
            train_windows=log.get("train_windows"), validation=m)
    order, q1 = rank_arms(val)
    for n in arms:
        report["arms"][n]["Q1"] = q1[n]
    gates = None
    if a.gates:
        reps, missing = load_gates(Path(a.gates), arms)
        if reps is None:
            report["gates_missing"] = missing
        else:
            gates = {n: gates_for(n, reps[n], reps) for n in arms}
            for n in arms:
                report["arms"][n]["gates"] = gates[n]
    report["decision"] = decide(order, q1, gates)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["decision"], indent=2))
    return report


if __name__ == "__main__":
    main()
