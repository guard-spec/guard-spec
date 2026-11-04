"""Benign FPR and TPR per language and surface variant on the validation splits only.

    cd train && uv run python variant_report.py --model ../models/local/guardspec-classifier-v1 \
        [--split data/val.jsonl --split data/val_hard.jsonl --split data/val_vi_variants.jsonl] [--thr 0.85]

Diagnostic for the Vietnamese no-diacritics / teencode false positives (classifier v2). It scores the
packaged INT8 model exactly as the gateway does (windows, max risk) and never reads eval/.
Thresholds: the model's calibrated risk_threshold, plus any --thr given.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

import numpy as np

from common_train import ROOT, auc, rates, read_jsonl
from evaluate import Ours

DEFAULT_SPLITS = ["data/val.jsonl", "data/val_hard.jsonl", "data/val_vi_variants.jsonl", "data/val_v3.jsonl"]


def report(model_dir: Path, splits, extra_thr):
    m = Ours(model_dir)
    thrs = [m.th["risk_threshold"]] + list(extra_thr)
    out = {"model": m.th.get("model"), "thresholds": thrs, "groups": {}}
    for sp in splits:
        p = ROOT / sp
        if not p.exists():
            continue
        rows = read_jsonl(p)
        risk, _, _ = m.score([r["text"] for r in rows])
        y = np.array([r["labels"] != ["benign"] for r in rows])
        g = collections.defaultdict(list)
        for i, r in enumerate(rows):
            g[f"{p.stem}/{r['lang']}"].append(i)
            g[f"{p.stem}/{r['lang']}/{r['variant']}"].append(i)
        for name, idx in sorted(g.items()):
            idx = np.array(idx)
            yy, ss = y[idx], risk[idx]
            e = dict(n_attack=int(yy.sum()), n_benign=int((~yy).sum()),
                     auc=auc(yy, ss) if yy.any() and (~yy).any() else None)
            for t in thrs:
                tpr, fpr = rates(yy, ss, t)
                e[f"tpr@{t:.4f}"], e[f"fpr@{t:.4f}"] = tpr, fpr
            out["groups"][name] = e
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--split", action="append")
    ap.add_argument("--thr", action="append", type=float, default=[])
    ap.add_argument("--json", help="write the report here")
    a = ap.parse_args()
    rep = report(Path(a.model).resolve(), a.split or DEFAULT_SPLITS, a.thr)
    thrs = rep["thresholds"]
    hdr = "| group | atk/ben | AUC | " + " | ".join(f"TPR / FPR @{t:.3f}" for t in thrs) + " |"
    print(f"model {rep['model']}\n\n{hdr}\n|" + "---|" * (3 + len(thrs)))
    f = lambda x: "-" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.3f}"  # noqa: E731
    for name, e in rep["groups"].items():
        cells = " | ".join(f"{f(e[f'tpr@{t:.4f}'])} / {f(e[f'fpr@{t:.4f}'])}" for t in thrs)
        print(f"| {name} | {e['n_attack']}/{e['n_benign']} | {f(e['auc'])} | {cells} |")
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
