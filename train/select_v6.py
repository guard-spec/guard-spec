"""Apply the pre-registered v6 arm-selection rule (MODEL_CARD.md, "v6", "Decision rule") and write
reports/train_arms_v6.json.

    uv run --frozen python select_v6.py --arm A=runs/v6/A --arm B=runs/v6/B --arm C=runs/v6/C \
        [--gates runs/v6/gates] [--out reports/train_arms_v6.json]

Inputs, all produced by run_arms_v6.sh:

- <run>/train_log.json and <run>/val_scores.jsonl of every arm (train.py): recorded, not a gate.
- --gates <dir>: per arm <dir>/<arm>/{eval,codelog,embedded,val_v3}.json (cmd/eval -json reports; eval/ on
  the direct path, codelog and embedded on the tool path with code corroboration off, val_v3 = the v4-A
  build's val_v3.jsonl on the direct path) and <dir>/<arm>/benchlong-full.json (cmd/benchlong, full
  profile, layers l1;l1,l2, the arm's calibration with its cap); <dir>/v3b/{eval,codelog,embedded,val_v3}.json
  and <dir>/l1/embedded.json for the references. Without --gates (or with reports missing) the gates are
  reported as pending and no arm is chosen.

Only `slices.dev` of the eval/ reports and the `dev` rows of the benchlong report are read. Never read:
the hold-out slices of eval/ and bench/long, val_v6_holdout, val_v3_holdout, the owner hold-outs.
Standard library only (the tests run it without the training environment).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from select_v5 import ORIGINAL_VAL, TARGET_FPR, auc, dev, rate, read_jsonl, threshold_at_fpr

ROOT = Path(__file__).resolve().parent
VAL_V6 = "val_v6"  # set B of the v6 builder (v6_val, set A's validation split, is for early stopping only)

# Thresholds of the rule (MODEL_CARD.md, v6). Changing one changes the pre-registered rule.
G2_MAX_FPR = 0.03          # eval/codelog dev FPR at 0.85, tool path, corroboration off
G5_MARGIN = 0.01           # val_v3 direct-path TPR at 0.85 may be at most 1 point under v3b's
G6_MAX_FPR = 0.01          # bench/long dev: blocked benign documents of 100k and 200k tokens, EN and VI pooled
G6_SIZES = ("100k", "200k")       # the size labels of the cmd/benchlong report
G7_MARGIN = 0.05           # bench/long dev: embedded-in-prose TPR at least the payloads' alone TPR - 5 points
G7_VARIANTS = ("pos_start", "pos_end", "pos_random",                 # positions
               "straddle_window", "straddle_chunk", "straddle_segment",  # boundaries
               "split_adjacent")                                      # split, both halves in one window
BENCH_LAYER = "l1,l2/logreg"  # the gateway's fused score on documents (no L3 on the long path)
BENCH_LANGS = ("en", "vi")
G1_DECIMALS = 4            # cmd/eval reports four decimals; equal values are a tie


# ---------------------------------------------------------------------------- recorded validation (no gate)

def validation_metrics(scores):
    """Original-validation threshold at benign FPR <= 1%, then val_v6 at that threshold (L2 alone, best
    epoch, PyTorch FP32, worst window per row). Recorded for the card; the v6 rule does not read it."""
    def split(rows):
        pos = [r["risk"] for r in rows if r["labels"] != ["benign"]]
        neg = [r["risk"] for r in rows if r["labels"] == ["benign"]]
        return pos, neg

    orig = [r for r in scores if r["file"] in ORIGINAL_VAL]
    v6 = [r for r in scores if r["file"] == VAL_V6]
    if not orig or not v6:
        raise SystemExit("val_scores.jsonl needs the original validation files and val_v6 (train.py --v6-dir)")
    op, on = split(orig)
    vp, vn = split(v6)
    t = threshold_at_fpr(on, TARGET_FPR)
    m = dict(threshold=t,
             orig=dict(n_attack=len(op), n_benign=len(on), auc=auc(op, on), tpr=rate(op, t), fpr=rate(on, t)),
             val_v6=dict(n_attack=len(vp), n_benign=len(vn), auc=auc(vp, vn), tpr=rate(vp, t), fpr=rate(vn, t)))
    by_kind = {}
    for r in v6:
        if r["labels"] == ["benign"]:
            by_kind.setdefault(r.get("kind") or "?", []).append(r["risk"])
    m["val_v6"]["fpr_by_kind"] = {k: rate(v, t) for k, v in sorted(by_kind.items())}
    return m


# ---------------------------------------------------------------------------- bench/long (dev rows only)

def clopper_pearson_upper(k, n, alpha=0.05):
    """Upper end of the two-sided (1 - alpha) Clopper-Pearson interval of k successes in n (0 < .. <= 1)."""
    if n <= 0:
        return float("nan")
    if k >= n:
        return 1.0

    def cdf(p):  # P(X <= k | n, p)
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))

    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if cdf(mid) > alpha / 2:
            lo = mid
        else:
            hi = mid
    return hi


def bench_dev_fpr(report, sizes=G6_SIZES, layer=BENCH_LAYER, langs=BENCH_LANGS):
    """Blocked benign documents of the dev slice at the block threshold (the `fpr` column of the report,
    the fused layer's own maximum), pooled over the sizes and languages. Returns (blocked, docs, per cell)."""
    rows = [r for r in report.get("doc_fpr_by_split", [])
            if r.get("layer") == layer and r.get("split") == "dev" and r.get("lang") in langs and str(r.get("size")) in sizes]
    if not rows:
        raise SystemExit(f"benchlong report without dev rows for layer {layer} and sizes {sizes}: run the full profile")
    blocked = docs = 0
    cells = {}
    for r in rows:
        b = round(r["fpr"] * r["docs"])
        blocked += b
        docs += r["docs"]
        cells[f"{r['lang']}/{r['size']}"] = dict(blocked=b, docs=r["docs"])
    return blocked, docs, cells


def bench_dev_tpr(report, variants, layer=BENCH_LAYER, langs=BENCH_LANGS):
    """Gateway detection of the dev attack documents of these variants, pooled over variants and languages.
    Returns (detected, docs)."""
    rows = [r for r in report.get("tpr_by_split", [])
            if r.get("layer") == layer and r.get("split") == "dev" and r.get("lang") in langs and r.get("variant") in variants]
    if not rows:
        raise SystemExit(f"benchlong report without dev rows for layer {layer} and variants {variants}")
    detected = sum(round(r["gateway_tpr"] * r["docs"]) for r in rows)
    return detected, sum(r["docs"] for r in rows)


# ---------------------------------------------------------------------------- the rule

def gates_for(arm, rep, ref):
    """G1-G7 of one arm. rep: {eval, codelog, embedded, val_v3, bench} of the arm; ref: v3b's and L1's."""
    g = {}
    a, b = dev(rep["eval"], "at_fpr_1pct", "tpr"), dev(ref["v3b"]["eval"], "at_fpr_1pct", "tpr")
    g["G1"] = dict(ok=a >= b, value=a, v3b=b, what="eval/data dev TPR at FPR <= 1% (fused, direct path) >= v3b")
    a = dev(rep["codelog"], "at_0.85", "fpr")
    g["G2"] = dict(ok=a <= G2_MAX_FPR, value=a, limit=G2_MAX_FPR,
                   what="eval/codelog dev FPR at 0.85 (tool path, corroboration off) <= 0.03")
    a = dev(rep["embedded"], "at_0.85", "tpr")
    b, c = dev(ref["v3b"]["embedded"], "at_0.85", "tpr"), dev(ref["l1"]["embedded"], "at_0.85", "tpr")
    g["G3"] = dict(ok=a >= b and a >= c, value=a, v3b=b, l1=c,
                   what="eval/embedded dev TPR at 0.85 (tool path, corroboration off) >= v3b and >= L1 alone")
    a, b = dev(rep["embedded"], "at_0.85", "fpr"), dev(ref["v3b"]["embedded"], "at_0.85", "fpr")
    g["G4"] = dict(ok=a <= b, value=a, v3b=b, what="eval/embedded dev FPR at 0.85 (tool path, corroboration off) <= v3b")
    a, b = top(rep["val_v3"], "at_0.85", "tpr"), top(ref["v3b"]["val_v3"], "at_0.85", "tpr")
    g["G5"] = dict(ok=a >= b - G5_MARGIN - 1e-12, value=a, v3b=b, margin=G5_MARGIN,
                   n_attack=rep["val_v3"].get("n_attack"),
                   what="val_v3 (the v4-A build's selection split, direct path) TPR at 0.85 >= v3b - 0.01")
    blocked, docs, cells = bench_dev_fpr(rep["bench"])
    g["G6"] = dict(ok=docs > 0 and blocked / docs <= G6_MAX_FPR, value=blocked / docs if docs else float("nan"),
                   blocked=blocked, docs=docs, cells=cells, limit=G6_MAX_FPR,
                   cp95_upper=clopper_pearson_upper(blocked, docs),
                   what="bench/long dev, l1,l2 with the arm's calibration and cap: blocked benign documents of 100k and "
                        "200k tokens (EN + VI) <= 1%; with 3-5 documents per cell this means none blocked")
    det, n = bench_dev_tpr(rep["bench"], G7_VARIANTS)
    cdet, cn = bench_dev_tpr(rep["bench"], ("control",))
    g["G7"] = dict(ok=n > 0 and cn > 0 and det / n >= cdet / cn - G7_MARGIN - 1e-12,
                   value=det / n if n else float("nan"), detected=det, docs=n,
                   alone=cdet / cn if cn else float("nan"), alone_detected=cdet, alone_docs=cn, margin=G7_MARGIN,
                   what="bench/long dev: gateway TPR of payloads in prose (start/end/random, window/chunk/segment "
                        "boundary, split adjacent; EN + VI) >= the same payloads alone (control) - 0.05")
    return g


def top(report, metric, field):
    """<metric>.<field> of a cmd/eval -json report over all its rows (G5 reads the whole val_v3 file)."""
    try:
        return report[metric][field]
    except (KeyError, TypeError):
        raise SystemExit(f"cmd/eval report without {metric}.{field}")


def rank_key(arm, gates):
    """Order among the arms that pass: higher G1 (four decimals), then fewer blocked bench documents (G6),
    then higher G3; the arm name last so the order is total."""
    g = gates[arm]
    return (-round(g["G1"]["value"], G1_DECIMALS), g["G6"]["value"], -g["G3"]["value"], arm)


def decide(arms, gates):
    """The arm passing every gate with the best rank_key. gates: {arm: gates_for(...)} or None."""
    if gates is None:
        return dict(status="gates pending", chosen=None, note="run the gates (run_arms_v6.sh gates) before choosing")
    passing = sorted((a for a in arms if all(x["ok"] for x in gates[a].values())), key=lambda a: rank_key(a, gates))
    names = sorted(gates[arms[0]])
    best_per_gate = {}
    for n in names:
        higher = n in ("G1", "G3", "G5", "G7")  # the others are rates to keep low
        best = max(arms, key=lambda a: (gates[a][n]["value"] if higher else -gates[a][n]["value"], a == arms[0]))
        best_per_gate[n] = dict(arm=best, value=gates[best][n]["value"], ok=gates[best][n]["ok"])
    met = {a: sum(x["ok"] for x in gates[a].values()) for a in arms}
    if passing:
        return dict(status="chosen", chosen=passing[0], order=passing, gates_met=met, best_per_gate=best_per_gate)
    fallback = max(arms, key=lambda a: (met[a], round(gates[a]["G1"]["value"], G1_DECIMALS), -arms.index(a)))
    return dict(status="no arm qualifies", chosen=None, gates_met=met, best_per_gate=best_per_gate,
                fallback_candidate=fallback,
                note="no arm is v6; the arm meeting most gates (tie: higher G1, then arm order) is reported as a "
                     "fallback candidate for the owner only: hold-outs are scored once for it and it is packaged "
                     "under guardspec-data as 'not selected', never added to the manifest or published")


# ---------------------------------------------------------------------------- main

def load_gates(gdir: Path, arms):
    names = list(arms) + ["v3b"]
    sets = ("eval", "codelog", "embedded", "val_v3")
    need = [gdir / n / f"{s}.json" for n in names for s in sets]
    need += [gdir / a / "benchlong-full.json" for a in arms] + [gdir / "l1" / "embedded.json"]
    missing = [str(p) for p in need if not p.exists()]
    if missing:
        return None, missing
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))  # noqa: E731
    reps = {n: {s: load(gdir / n / f"{s}.json") for s in sets} for n in names}
    for a in arms:
        reps[a]["bench"] = load(gdir / a / "benchlong-full.json")
    reps["l1"] = {"embedded": load(gdir / "l1" / "embedded.json")}
    return reps, []


def recorded(rep, ref):
    """Numbers the card records next to the gates, not part of the rule: latency per row on the direct
    path versus v3b (cmd/eval latency), and the bench/long score pass."""
    out = {}
    try:
        a, b = rep["eval"]["latency"]["all"]["p50_us"], ref["v3b"]["eval"]["latency"]["all"]["p50_us"]
        out["eval_latency_p50_us"] = dict(value=a, v3b=b, ratio=a / b if b else None)
    except (KeyError, TypeError):
        pass
    sp = rep["bench"].get("score_pass") or {}
    if sp:
        out["bench_score_pass"] = dict(tokens_per_s=sp.get("tokens_per_s"), cpu_s=sp.get("cpu_s"), l2_windows=sp.get("l2_windows"))
    out["bench_l2_cap"] = (rep["bench"].get("header") or {}).get("l2_cap")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", required=True, metavar="NAME=RUN_DIR")
    ap.add_argument("--gates", help="directory with the cmd/eval and cmd/benchlong reports (see the module docstring)")
    ap.add_argument("--out", default=str(ROOT / "reports" / "train_arms_v6.json"))
    a = ap.parse_args(argv)
    arms = dict(s.split("=", 1) for s in a.arm)
    report = dict(rule="MODEL_CARD.md, v6, Decision rule (pre-registered)", arms={})
    for name, run in arms.items():
        run = Path(run) if Path(run).is_absolute() else ROOT / run
        log = json.loads((run / "train_log.json").read_text(encoding="utf-8"))
        ep = {e["epoch"]: e for e in log["epochs"]}
        m = validation_metrics(read_jsonl(run / "val_scores.jsonl"))
        m["val_loss"] = ep[log["best_epoch"]]["val_loss"]
        report["arms"][name] = dict(
            n_train_rows_per_epoch=log.get("n_train_rows"), n_train_windows_per_epoch=log.get("n_train"),
            n_val_windows=log.get("n_val"), best_epoch=log["best_epoch"],
            train_minutes=round(log["train_seconds"] / 60, 1), seed=log["config"].get("seed"),
            val_loss=[round(e["val_loss"], 4) for e in log["epochs"]],
            oversample=log["config"]["train"].get("oversample"), oversample_kind=log["config"]["train"].get("oversample_kind"),
            train_files=[Path(p).name for p in log["config"]["data"].get("train_files", [])],
            train_windows=log.get("train_windows"), validation=m)
    gates = None
    if a.gates:
        reps, missing = load_gates(Path(a.gates), list(arms))
        if reps is None:
            report["gates_missing"] = missing
        else:
            gates = {n: gates_for(n, reps[n], reps) for n in arms}
            for n in arms:
                report["arms"][n]["gates"] = gates[n]
                report["arms"][n]["recorded"] = recorded(reps[n], reps)
    report["decision"] = decide(list(arms), gates)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["decision"], indent=2))
    return report


if __name__ == "__main__":
    main()
