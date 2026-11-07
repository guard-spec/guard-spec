"""Per-group false-positive and recall tables for choosing between classifier candidates (v4).

    cd train && uv run python select_report.py --data-dir <GUARD_BUILD_OUT> \\
        --model v3b=<val_cache.json>,<holdout_scores.jsonl> --model A=... [--owner-holdout <file>] \\
        --json reports/select_report_v4.json --md reports/select_report_v4.md

Inputs per model (both made by the gateway's own code, never by re-implementing it):

- validation: the raw L1/L2/L3 scores that `go run -tags onnx ./cmd/calibrate fit -cache <file>` writes for the
  validation splits. They are fused out of fold here (5 folds by FNV-32a of the row id, Platt on L2 and the
  logistic regression refitted on the other folds, built-in L1 and L3 scalings), as `cmd/calibrate` does.
  The L1 floor is not applied (L1 is the same for every model; the floor only raises scores).
- hold-outs and probes: `go run -tags onnx ./cmd/calibrate` is not used; the rows go through
  `cmd/eval -detector fusion-ml -scores <file>`, i.e. the gateway path with the model's calibration and the
  L1 floor, and `blocked` is the gateway's decision.

`--owner-holdout` (optional, never committed) adds the owner's `batch` and `ablate` tags to the owner
hold-out groups. The output holds aggregate counts only, never row text. eval/ is never read.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
from pathlib import Path

import numpy as np

from common_train import auc

VAL_SPLITS = ("val", "val_hard", "val_vi_variants", "val_v3", "val_v4")
HOLD_SPLITS = ("val_v3_holdout", "val_realistic_holdout", "val_v4_holdout", "user_holdout", "otpkyc_probe", "probe_v4")
EXTERNAL = ("guard-spec:owner-supplied", "guard-spec:otpkyc-fable")
EPS = 1e-4
L1CAL = (0.998, 0.356)  # fusion.DefaultL1Calibration
L3CAL = (3.2567, -0.9815)  # ml.DefaultL3Calibration
BLOCK = 0.85


def logit(p):
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


def sig(x):
    return 1 / (1 + np.exp(-x))


def fnv32a(s):
    h = 0x811C9DC5
    for b in s.encode():
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def platt(s, y):
    """fusion.FitPlatt: Newton on the logit with Platt's smoothed targets."""
    npos, nneg = y.sum(), (~y).sum()
    t = np.where(y, (npos + 1) / (npos + 2), 1 / (nneg + 2))
    x = logit(s)
    a, b = 1.0, 0.0
    for _ in range(100):
        p = sig(a * x + b)
        d = p - t
        w = np.maximum(p * (1 - p), 1e-12)
        g = np.array([(d * x).sum(), d.sum()])
        hess = np.array([[(w * x * x).sum() + 1e-9, (w * x).sum()], [(w * x).sum(), w.sum() + 1e-9]])
        st = np.linalg.solve(hess, g)

        def loss(a_, b_):
            z = a_ * x + b_
            return (np.maximum(z, 0) + np.log1p(np.exp(-np.abs(z))) - t * z).sum()
        cur, step = loss(a, b), 1.0
        while step > 1e-10 and loss(a - step * st[0], b - step * st[1]) > cur + 1e-12:
            step /= 2
        a, b = a - step * st[0], b - step * st[1]
        if abs(step * st[0]) < 1e-9 and abs(step * st[1]) < 1e-9:
            break
    return a, b


def logreg(P, y, lam=0.01):
    """fusion.FitLogReg: ridge logistic regression on the logits of the calibrated layer scores."""
    X = np.concatenate([logit(P), np.ones((len(P), 1))], axis=1)
    th = np.zeros(X.shape[1])
    for _ in range(100):
        q = sig(X @ th)
        w = np.maximum(q * (1 - q), 1e-12)
        g = X.T @ (q - y)
        H = (X * w[:, None]).T @ X
        g[:-1] += lam * th[:-1]
        H[np.arange(len(th) - 1), np.arange(len(th) - 1)] += lam
        st = np.linalg.solve(H + 1e-9 * np.eye(len(th)), g)
        th -= st
        if np.abs(st).max() < 1e-9:
            break
    return th


def calp(raw, c):
    return sig(c[0] * logit(raw) + c[1])


def fused_oof(raw, y, ids, k=5):
    fold = np.array([fnv32a(i) % k for i in ids])
    out = np.zeros(len(y))
    for f in range(k):
        tr = fold != f
        c2 = platt(raw[tr, 1], y[tr])
        P = np.stack([calp(raw[:, 0], L1CAL), calp(raw[:, 1], c2), calp(raw[:, 2], L3CAL)], axis=1)
        th = logreg(P[tr], y[tr].astype(float))
        out[~tr] = sig(logit(P[~tr]) @ th[:-1] + th[-1])
    return out


def read_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def load_meta(data_dir, owner_holdout):
    tags = {}
    if owner_holdout:
        for r in read_jsonl(owner_holdout):
            tags[r["text"].strip()] = (r.get("batch") or "ud1", bool(r.get("ablate")))
    meta = {}
    for sp in VAL_SPLITS + HOLD_SPLITS:
        p = Path(data_dir) / f"{sp}.jsonl"
        if not p.exists():
            continue
        for r in read_jsonl(p):
            m = dict(split=sp, lang=r["lang"], variant=r["variant"], source=r["source"], group=r["group"],
                     attack=r["labels"] != ["benign"])
            if sp == "user_holdout" and r["text"].strip() in tags:
                m["batch"], m["ablate"] = tags[r["text"].strip()]
            meta[r["id"]] = m
    return meta


def groups(rid, m):
    sp, lang, var = m["split"], m["lang"], m["variant"]
    vi_var = f"{lang}/{var}" if lang == "vi" else lang
    if sp in VAL_SPLITS:
        yield "validation/all"
        yield f"validation/{vi_var}"
        yield f"validation/split {sp}"
        if m["source"] in EXTERNAL:
            yield "validation/owner+otpkyc rows"
        return
    yield f"{sp}/all"
    if sp == "user_holdout":
        yield f"{sp}/{lang}"
        if "batch" in m:
            yield f"{sp}/batch {m['batch']}"
            if m["batch"] == "ud2teen":
                yield f"{sp}/batch ud2teen/{var}"
            if m["ablate"]:
                yield f"{sp}/ablate"
        if m["group"].startswith(("udbank.", "ud2bank.")):
            yield f"{sp}/banking (udbank + ud2bank)"
    elif sp == "otpkyc_probe":
        yield f"{sp}/{lang}"
    elif sp == "probe_v4":
        yield f"{sp}/sentence {m['group'].rsplit('.', 1)[1]}"
    else:
        yield f"{sp}/{vi_var}"
    if lang == "vi" and var in ("teencode", "no_diacritics"):
        yield f"holdouts/vi/{var} (all hold-outs)"
    # R1 pool of the v4 decision rule: Vietnamese benign rows of the owner hold-out, val_v4_holdout, probe_v4.
    if not m["attack"] and lang == "vi" and sp in ("user_holdout", "val_v4_holdout", "probe_v4"):
        yield "R1 pool: VI benign (user_holdout + val_v4_holdout + probe_v4)"
    if sp in ("val_v3_holdout", "val_realistic_holdout"):
        yield "R5 pool: val_v3_holdout + val_realistic_holdout"


def tally(rows):
    g = collections.defaultdict(lambda: dict(benign=0, fp=0, attack=0, tp=0, s=[], y=[]))
    for rid, m, score, blocked in rows:
        for k in groups(rid, m):
            e = g[k]
            if m["attack"]:
                e["attack"] += 1
                e["tp"] += bool(blocked)
            else:
                e["benign"] += 1
                e["fp"] += bool(blocked)
            e["s"].append(score)
            e["y"].append(m["attack"])
    out = {}
    for k, e in g.items():
        out[k] = dict(benign=e["benign"], fp=e["fp"], attack=e["attack"], tp=e["tp"],
                      fpr=e["fp"] / e["benign"] if e["benign"] else None,
                      tpr=e["tp"] / e["attack"] if e["attack"] else None,
                      auc=auc(e["y"], e["s"]) if e["benign"] and e["attack"] else None)
    return out


def score_model(spec, meta):
    val_cache, hold_scores = spec.split(",")
    val = [r for r in json.loads(Path(val_cache).read_text()) if r["id"] in meta]
    raw = np.array([r["raw"] for r in val])
    y = np.array([r["attack"] for r in val])
    ids = [r["id"] for r in val]
    oof = fused_oof(raw, y, ids)
    p = np.clip(oof, 1e-7, 1 - 1e-7)
    summary = dict(val_rows=len(val), val_oof_auc=auc(y, oof),
                   val_oof_logloss=float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))))
    rows = [(i, meta[i], float(s), s >= BLOCK) for i, s in zip(ids, oof)]
    hold = [r for r in read_jsonl(hold_scores) if r["id"] in meta]
    rows += [(r["id"], meta[r["id"]], float(r["score"]), bool(r["blocked"])) for r in hold]
    summary["holdout_rows"] = len(hold)
    probe = sorted((meta[r["id"]]["group"], r["score"]) for r in hold if meta[r["id"]]["split"] == "probe_v4")
    summary["probe_v4_scores"] = [round(s, 4) for _, s in probe]
    return summary, tally(rows)


def cell(e):
    if e is None:
        return "-"
    fp = f"{e['fpr']:.1%} ({e['fp']})" if e["benign"] else "-"
    tp = f"{e['tpr']:.3f}" if e["attack"] else "-"
    return f"{fp} / {tp}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--owner-holdout")
    ap.add_argument("--model", action="append", required=True, metavar="TAG=VAL_CACHE,HOLDOUT_SCORES")
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args()
    meta = load_meta(a.data_dir, a.owner_holdout)
    res, order = {}, []
    for spec in a.model:
        tag, files = spec.split("=", 1)
        res[tag] = score_model(files, meta)
        order.append(tag)
    keys = sorted(set().union(*[set(t) for _, t in res.values()]))
    lines = ["| model | validation rows | validation OOF AUC | validation OOF log loss | probe_v4 fused scores |",
             "|---|---|---|---|---|"]
    for t in order:
        s = res[t][0]
        lines.append(f"| {t} | {s['val_rows']} | {s['val_oof_auc']:.4f} | {s['val_oof_logloss']:.4f} | "
                     f"{', '.join(f'{x:.3f}' for x in s['probe_v4_scores'])} |")
    lines += ["", "| group | benign / attack | " + " | ".join(f"{t} FPR / TPR" for t in order) + " |",
              "|---|---|" + "---|" * len(order)]
    for k in keys:
        e0 = next(res[t][1][k] for t in order if k in res[t][1])
        lines.append(f"| {k} | {e0['benign']} / {e0['attack']} | " +
                     " | ".join(cell(res[t][1].get(k)) for t in order) + " |")
    md = "\n".join(lines) + "\n"
    print(md)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if a.json:
        out = {t: dict(summary=res[t][0], groups=res[t][1]) for t in order}
        Path(a.json).write_text(json.dumps(dict(block_threshold=BLOCK, models=out), indent=2,
                                           default=lambda x: None if isinstance(x, float) and math.isnan(x) else x)
                                + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
