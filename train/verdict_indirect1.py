# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Verdict of the indirect1 holdout (RF-67fdf675), as pre-registered in train/reports/indirect1_preregistration.md.

Reads the `cmd/eval -scores` files of the reference (v3b with main's rules) and the candidate, computes C1 (TPR
difference with a paired bootstrap interval) and C2 (Clopper-Pearson upper bound of the candidate's FPR), and the
per-stratum table. Uses the gateway's decision (`blocked`). Standard library only.

    python3 train/verdict_indirect1.py --dir <holdout scores dir> --out train/reports/indirect1_holdout.json
"""
from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

SEED = 20261116
B = 10_000


def load(p: Path) -> dict[str, dict]:
    return {r["id"]: r for r in (json.loads(l) for l in p.open(encoding="utf-8"))}


def stratum(rid: str) -> str:
    return rid.split("-")[1]


def beta_ppf(q: float, a: float, b: float) -> float:
    """Inverse of the regularized incomplete beta, by bisection on a continued-fraction CDF."""
    def cdf(x: float) -> float:
        if x <= 0:
            return 0.0
        if x >= 1:
            return 1.0
        lb = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
        if x < (a + 1) / (a + b + 2):
            return math.exp(lb) * _cf(x, a, b) / a
        return 1 - math.exp(lb) * _cf(1 - x, b, a) / b
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if cdf(mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _cf(x: float, a: float, b: float) -> float:
    tiny = 1e-300
    c, d = 1.0, 1 - (a + b) * x / (a + 1)
    d = 1 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((a + m2 - 1) * (a + m2))
        d = 1 + aa * d; d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / c if abs(c) > tiny else 1 + aa / tiny
        h *= d * c
        aa = -(a + m) * (a + b + m) * x / ((a + m2) * (a + m2 + 1))
        d = 1 + aa * d; d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / c if abs(c) > tiny else 1 + aa / tiny
        de = d * c
        h *= de
        if abs(de - 1) < 1e-12:
            break
    return h


def cp_upper(k: int, n: int, conf: float = 0.95) -> float:
    return 1.0 if k >= n else beta_ppf(conf + (1 - conf) / 2, k + 1, n - k)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()
    sys_ = {n: load(a.dir / f"{n}.scores.jsonl") for n in ("ref-v3b", "ref-v8e", "cand-v3b", "cand-v8e")}
    ids = sorted(sys_["ref-v3b"])
    assert all(sorted(s) == ids for s in sys_.values()), "the systems scored different rows"
    att = [i for i in ids if sys_["ref-v3b"][i]["label"] == "attack"]
    ben = [i for i in ids if sys_["ref-v3b"][i]["label"] == "benign"]

    def rate(name: str, rows: list[str]) -> tuple[int, int]:
        return sum(bool(sys_[name][i]["blocked"]) for i in rows), len(rows)

    ref, cand = sys_["ref-v3b"], sys_["cand-v3b"]
    d = [int(cand[i]["blocked"]) - int(ref[i]["blocked"]) for i in att]
    rng = random.Random(SEED)
    boots = sorted(sum(d[rng.randrange(len(d))] for _ in d) / len(d) for _ in range(B))
    diff = sum(d) / len(d)
    lo, hi = boots[int(0.025 * B)], boots[int(0.975 * B) - 1]
    fp, nb = rate("cand-v3b", ben)
    up = cp_upper(fp, nb)
    tr, _ = rate("ref-v3b", att)
    tc, _ = rate("cand-v3b", att)
    c1 = (tc - tr) / len(att) >= 0.15 and lo > 0.10
    c2 = up <= 0.03
    out = {
        "rows": {"attack": len(att), "benign": len(ben)},
        "C1": {"ref_tpr": tr / len(att), "cand_tpr": tc / len(att), "diff": diff, "ci95": [lo, hi], "pass": c1},
        "C2": {"cand_fp": fp, "benign": nb, "fpr": fp / nb, "cp95_upper": up, "pass": c2},
        "pass": c1 and c2,
        "systems": {},
    }
    strata = sorted({stratum(i) for i in ids})
    for n in sys_:
        row = {}
        for s in strata + ["ALL"]:
            for lab in ("attack", "benign"):
                rs = [i for i in ids if sys_[n][i]["label"] == lab and (s == "ALL" or stratum(i) == s)]
                if rs:
                    k, m = rate(n, rs)
                    row[f"{s}/{lab}"] = {"blocked": k, "rows": m, "rate": k / m}
        out["systems"][n] = row
    a.out.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: out[k] for k in ("rows", "C1", "C2", "pass")}, indent=1))


if __name__ == "__main__":
    main()
