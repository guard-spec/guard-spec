# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Long document rule of the long path: fit, select and evaluate (RF-895d3533 R3).

Reads the window scores `cmd/benchlong -long on -dump` writes (one gzipped JSONL
file per bench split: benign long documents, and payloads alone and embedded in
long documents, `bench/long/embed_long.py`) and applies the candidate rules of
train/reports/r3_preregistration.md:

    fit     dev only: fits the parameters of every candidate, measures them on
            the dev slice and applies the pre-registered selection rule;
            writes <out>/r3_dev.json and .md.
    holdout the chosen rule with the parameters of `fit` (read from
            r3_dev.json), once, on the holdout slice; writes r3_holdout.json
            and .md.

    uv run --frozen python longdoc_r3.py fit --benign <dump>-dev.jsonl.gz \\
        --attack <attack dump>-dev.jsonl.gz --out <dir>
    uv run --frozen python longdoc_r3.py holdout --benign <dump>-holdout.jsonl.gz \\
        --attack <attack dump>-holdout.jsonl.gz --out <dir>

Only scores are read, never text. Nothing here reads a holdout file in `fit`.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import sys
from pathlib import Path

import numpy as np

THETA = 0.85          # the gateway's block threshold
ALPHA = 0.01          # target document false-positive rate
GEV_BLOCK = 16        # windows per block maximum in the GEV fit
DRAWS = 20000         # bootstrap draws per n
SEED = 20261111
N_GRID = [16, 32, 64, 128, 256, 512, 1024, 2048]
K_GRID = [2, 3, 4, 5, 6, 8]
TPR_MARGIN = 0.05     # embedded TPR >= alone TPR - 0.05
EMBED_VARIANTS = ["pos_start", "pos_end", "pos_random", "straddle_window", "straddle_chunk", "straddle_segment",
                  "split_adjacent"]
# Candidate order for the last tie-break: fewer parameters first.
CANDIDATES = ["corr", "kofn", "tn", "combo"]


# ---------------------------------------------------------------------------
# Data


def load(path: str | None) -> list[dict]:
    if not path:
        return []
    out = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            w = d.get("windows") or []
            d["p"] = np.array([x["p"] for x in w], dtype=float)
            d["c"] = np.array([bool(x.get("c")) for x in w], dtype=bool)
            d["span"] = np.array([[x["s"], x["e"]] for x in w], dtype=np.int64).reshape(-1, 2)
            del d["windows"]
            out.append(d)
    return out


def size_label(tokens: int) -> str:
    for g in (20000, 50000, 100000, 200000, 500000):
        if g * 9 // 10 <= tokens <= g * 11 // 10:
            return f"{g // 1000}k"
    return "other"


def logit(p):
    p = np.clip(p, 1e-9, 1 - 1e-9)
    return np.log(p / (1 - p))


def sigmoid(z):
    return 1 / (1 + np.exp(-z))


def clopper_pearson(k: int, n: int, conf: float = 0.95) -> tuple[float, float]:
    """Exact binomial interval, by bisection on the binomial CDF (no scipy)."""
    if n == 0:
        return (float("nan"), float("nan"))
    a = (1 - conf) / 2

    def cdf(x, p):  # P(X <= x)
        if p <= 0:
            return 1.0
        if p >= 1:
            return 0.0 if x < n else 1.0
        lp, lq = math.log(p), math.log1p(-p)
        s = 0.0
        for i in range(0, x + 1):
            s += math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq)
        return s

    def root(f, target, increasing):
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            if (f(mid) < target) == increasing:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    # lower: P(X >= k | p) = a (increasing in p); upper: P(X <= k | p) = a (decreasing).
    lower = 0.0 if k == 0 else root(lambda p: 1 - cdf(k - 1, p), a, True)
    upper = 1.0 if k == n else root(lambda p: cdf(k, p), a, False)
    return (lower, upper)


# ---------------------------------------------------------------------------
# Extreme values (cmd/benchlong stats.go, ported)


def sliding_max(x: np.ndarray, n: int) -> np.ndarray:
    m = len(x)
    if n >= m:
        return np.full(m, x.max())
    xx = np.concatenate([x, x[: n - 1]])  # circular, as cmd/benchlong slidingMax
    return np.lib.stride_tricks.sliding_window_view(xx, n).max(axis=1)[:m]


def block_bootstrap_q(stream: np.ndarray, n: int, q: float, rng) -> float:
    sm = sliding_max(stream, n)
    sample = sm[rng.integers(0, len(sm), DRAWS)]
    return float(np.quantile(sample, q))


def fit_gev(stream: np.ndarray, m: int) -> dict | None:
    k_blocks = len(stream) // m
    if k_blocks < 20:
        return None
    maxima = np.sort(logit(stream[: k_blocks * m].reshape(k_blocks, m)).max(axis=1))
    n = float(len(maxima))
    i = np.arange(len(maxima), dtype=float)
    b0 = maxima.mean()
    b1 = (i / (n - 1) * maxima).mean()
    b2 = (i * (i - 1) / ((n - 1) * (n - 2)) * maxima).mean()
    l1, l2, l3 = b0, 2 * b1 - b0, 6 * b2 - 6 * b1 + b0
    if l2 <= 0:
        return None
    g = {"block": m, "blocks": int(n), "gumbel_alpha": l2 / math.log(2)}
    g["gumbel_xi"] = l1 - 0.5772156649015329 * g["gumbel_alpha"]
    t3 = l3 / l2
    c = 2 / (3 + t3) - math.log(2) / math.log(3)
    k = 7.8590 * c + 2.9554 * c * c
    if abs(k) < 1e-6:
        g.update(k=0.0, alpha=g["gumbel_alpha"], xi=g["gumbel_xi"])
        return g
    gam = math.gamma(1 + k)
    g["k"] = k
    g["alpha"] = l2 * k / ((1 - 2 ** (-k)) * gam)
    g["xi"] = l1 - g["alpha"] * (1 - gam) / k
    return g


def gev_quantile(g: dict, n: int, q: float) -> float:
    y = -math.log(q ** (g["block"] / n))
    if g["k"] == 0:
        return float(sigmoid(g["gumbel_xi"] - g["gumbel_alpha"] * math.log(y)))
    return float(sigmoid(g["xi"] + g["alpha"] / g["k"] * (1 - y ** g["k"])))


def t_of_n(table: list[list[float]], n: int) -> float:
    """T(n) from the fitted table [[n, T], ...]: THETA up to the first point,
    linear in (ln n, logit T) between points, the last T beyond."""
    if n <= table[0][0]:
        return max(THETA, table[0][1]) if n == table[0][0] else THETA
    for (n0, t0), (n1, t1) in zip(table, table[1:]):
        if n <= n1:
            f = (math.log(n) - math.log(n0)) / (math.log(n1) - math.log(n0))
            return float(sigmoid((1 - f) * logit(t0) + f * logit(t1)))
    return table[-1][1]


# ---------------------------------------------------------------------------
# Rules: each returns, for a document, the boolean array of windows that block.


def hits(rule: str, params: dict, d: dict) -> np.ndarray:
    p, c = d["p"], d["c"]
    n = len(p)
    base = p >= THETA
    if rule == "base" or n <= params.get("n0", 0):
        return base
    if rule == "corr":
        return base & c
    if rule == "tn":
        return p >= t_of_n(params["t"], n)
    if rule == "combo":
        return (base & c) | (p >= t_of_n(params["t"], n))
    if rule == "kofn":
        return base if base.sum() >= params["k"] else np.zeros(n, dtype=bool)
    raise ValueError(rule)


def blocked(rule: str, params: dict, d: dict) -> bool:
    return bool(hits(rule, params, d).any())


def payload_windows(d: dict) -> np.ndarray:
    """Windows that overlap a payload span of the sanitized text."""
    sel = np.zeros(len(d["p"]), dtype=bool)
    for s, e in d.get("payload_spans") or []:
        if s < 0:
            continue
        sel |= (d["span"][:, 0] < e) & (d["span"][:, 1] > s)
    return sel


# ---------------------------------------------------------------------------
# Measurement


def rate(k: int, n: int) -> dict:
    lo, hi = clopper_pearson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "cp95": [lo, hi]}


def measure(rule: str, params: dict, benign: list[dict], attack: list[dict]) -> dict:
    out: dict = {"rule": rule, "params": {k: v for k, v in params.items()}}
    # Benign: model decision on scored documents of 100k and 200k tokens.
    cells: dict[tuple[str, str], list[int]] = {}
    for d in benign:
        if d.get("rejected") or d["kind"] != "benign":
            continue
        key = (d["lang"], size_label(d["tokens"]))
        cells.setdefault(key, [0, 0])
        cells[key][1] += 1
        cells[key][0] += blocked(rule, params, d)
    out["benign"] = {f"{l}-{s}": rate(*v) for (l, s), v in sorted(cells.items())}
    for lang in ("en", "vi"):
        k = sum(v[0] for (l, s), v in cells.items() if l == lang and s in ("100k", "200k"))
        n = sum(v[1] for (l, s), v in cells.items() if l == lang and s in ("100k", "200k"))
        out["benign"][f"{lang}-100k+200k"] = rate(k, n)
    for size in ("100k", "200k"):
        k = sum(v[0] for (l, s), v in cells.items() if s == size)
        n = sum(v[1] for (l, s), v in cells.items() if s == size)
        out["benign"][f"both-{size}"] = rate(k, n)
    k = sum(v[0] for (l, s), v in cells.items() if s in ("100k", "200k"))
    n = sum(v[1] for (l, s), v in cells.items() if s in ("100k", "200k"))
    out["benign"]["all"] = rate(k, n)

    # Attacks: control (alone) and embedded, per variant and pooled; the
    # document decision, and the decision on the payload's own windows.
    acc: dict[str, list[int]] = {}
    excluded = 0
    for d in attack:
        if d["kind"] not in ("attack", "control"):
            continue
        if d["kind"] == "attack" and d.get("intact") is False:
            excluded += 1
            continue
        v = d.get("variant") or "control"
        h = hits(rule, params, d) if not d.get("rejected") else None
        doc = bool(h.any()) if h is not None else False
        pay = bool((h & payload_windows(d)).any()) if h is not None and d["kind"] == "attack" else doc
        for key in (v, f"{d['lang']}:{v}") + (("embedded", f"{d['lang']}:embedded") if v in EMBED_VARIANTS else ()):
            a = acc.setdefault(key, [0, 0, 0])
            a[0] += doc
            a[1] += pay
            a[2] += 1
    out["attack"] = {k: {"doc": rate(a[0], a[2]), "payload": rate(a[1], a[2])} for k, a in sorted(acc.items())}
    out["attack_excluded_not_intact"] = excluded
    return out


# ---------------------------------------------------------------------------
# Fit (dev)


def fit(benign: list[dict], attack: list[dict]) -> dict:
    scored = [d for d in benign if not d.get("rejected") and d["kind"] == "benign" and len(d["p"])]
    stream = np.concatenate([d["p"] for d in scored])
    exceed = int((stream >= THETA).sum())
    p_hat = exceed / len(stream)
    n0 = int(math.floor(math.log(1 - ALPHA) / math.log(1 - p_hat))) if p_hat > 0 else 10**9
    rng = np.random.default_rng(SEED)
    g = fit_gev(stream, GEV_BLOCK)
    table = []
    for n in N_GRID:
        boot = block_bootstrap_q(stream, n, 1 - ALPHA, rng)
        gev = gev_quantile(g, n, 1 - ALPHA) if g else float("nan")
        table.append([n, max(THETA, boot, gev if g else THETA), boot, gev])
    t = [[row[0], row[1]] for row in table]
    fitted = {"windows": int(len(stream)), "documents": len(scored), "exceed_at_theta": exceed, "p_hat": p_hat,
              "n0": n0, "gev": g, "t_table": table}

    # k of n: the smallest k whose dev benign 100k + 200k document rate is at most ALPHA.
    k_choice = None
    k_scan = []
    for k in K_GRID:
        m = measure("kofn", {"n0": n0, "k": k}, benign, [])["benign"]["all"]
        k_scan.append([k, m["k"], m["n"]])
        if k_choice is None and m["k"] <= ALPHA * m["n"]:
            k_choice = k
    fitted["k_scan"] = k_scan
    params = {
        "base": {},
        "corr": {"n0": n0},
        "tn": {"n0": n0, "t": t},
        "combo": {"n0": n0, "t": t},
        "kofn": {"n0": n0, "k": k_choice if k_choice is not None else K_GRID[-1]},
    }
    results = {r: measure(r, params[r], benign, attack) for r in ["base"] + CANDIDATES}

    # Selection (pre-registered).
    def criteria(r):
        m = results[r]
        b = m["benign"]["all"]
        emb = m["attack"]["embedded"]["doc"]["rate"]
        alone = m["attack"]["control"]["doc"]["rate"]
        return {"fpr_ok": b["k"] <= ALPHA * b["n"], "tpr_ok": emb >= alone - TPR_MARGIN - 1e-12,
                "blocked": b["k"], "embedded_tpr": emb, "alone_tpr": alone}

    crit = {r: criteria(r) for r in CANDIDATES}
    if k_choice is None:
        crit["kofn"]["fpr_ok"] = False
    both = [r for r in CANDIDATES if crit[r]["fpr_ok"] and crit[r]["tpr_ok"]]
    order = lambda r: (-crit[r]["embedded_tpr"], crit[r]["blocked"], CANDIDATES.index(r))  # noqa: E731
    if both:
        chosen, why = sorted(both, key=order)[0], "meets both criteria"
    else:
        tpr_only = [r for r in CANDIDATES if crit[r]["tpr_ok"]]
        if tpr_only:
            chosen = sorted(tpr_only, key=lambda r: (crit[r]["blocked"], -crit[r]["embedded_tpr"], CANDIDATES.index(r)))[0]
            why = "no candidate meets both; fewest dev benign blocks among those meeting the TPR criterion"
        else:
            chosen, why = None, "no candidate meets the TPR criterion: no rule"
    return {"fitted": fitted, "params": params, "results": results, "criteria": crit, "chosen": chosen, "why": why}


# ---------------------------------------------------------------------------
# Reports


def fmt_rate(r: dict) -> str:
    if not r["n"]:
        return "-"
    return f"{r['k']} / {r['n']} ({100 * r['rate']:.1f}%, CP95 {100 * r['cp95'][0]:.1f}–{100 * r['cp95'][1]:.1f}%)"


def md_results(results: dict, rules: list[str]) -> str:
    lines = []
    keys = ["en-100k", "en-200k", "vi-100k", "vi-200k", "en-100k+200k", "vi-100k+200k", "both-100k", "both-200k", "all"]
    lines.append("| benign blocked | " + " | ".join(rules) + " |")
    lines.append("|---|" + "---|" * len(rules))
    for k in keys:
        lines.append(f"| {k} | " + " | ".join(fmt_rate(results[r]["benign"][k]) if k in results[r]["benign"] else "-" for r in rules) + " |")
    lines.append("")
    lines.append("| detection (document / payload windows) | " + " | ".join(rules) + " |")
    lines.append("|---|" + "---|" * len(rules))
    akeys = ["control"] + EMBED_VARIANTS + ["embedded", "en:control", "en:embedded", "vi:control", "vi:embedded"]
    for k in akeys:
        cells = []
        for r in rules:
            a = results[r]["attack"].get(k)
            cells.append("-" if not a else f"{fmt_rate(a['doc'])} / {100 * a['payload']['rate']:.1f}%")
        lines.append(f"| {k} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["fit", "holdout"])
    ap.add_argument("--benign", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.stage == "fit":
        if "holdout" in args.benign or "holdout" in args.attack:
            raise SystemExit("fit reads dev files only")
        rep = fit(load(args.benign), load(args.attack))
        (out / "r3_dev.json").write_text(json.dumps(rep, indent=1, default=float) + "\n", "utf-8")
        md = [f"# R3 dev fit\n\nchosen: **{rep['chosen']}** ({rep['why']})\n",
              f"fitted: windows {rep['fitted']['windows']}, exceedances at {THETA} {rep['fitted']['exceed_at_theta']}, "
              f"p_hat {rep['fitted']['p_hat']:.2e}, n0 {rep['fitted']['n0']}\n",
              "T(n): " + ", ".join(f"{int(r[0])}: {r[1]:.4f} (boot {r[2]:.4f}, gev {r[3]:.4f})" for r in rep['fitted']['t_table']) + "\n",
              f"k scan (k, blocked, docs): {rep['fitted']['k_scan']}\n",
              "criteria: " + json.dumps(rep["criteria"]) + "\n\n",
              md_results(rep["results"], ["base"] + CANDIDATES)]
        (out / "r3_dev.md").write_text("\n".join(md), "utf-8")
        print((out / "r3_dev.md").read_text("utf-8"))
        return 0
    dev = json.loads((out / "r3_dev.json").read_text("utf-8"))
    chosen = dev["chosen"]
    rules = ["base"] + ([chosen] if chosen else [])
    benign, attack = load(args.benign), load(args.attack)
    res = {r: measure(r, dev["params"][r], benign, attack) for r in rules}
    rep = {"chosen": chosen, "params": dev["params"].get(chosen) if chosen else None, "results": res}
    (out / "r3_holdout.json").write_text(json.dumps(rep, indent=1, default=float) + "\n", "utf-8")
    md = f"# R3 holdout (once)\n\nchosen: **{chosen}**\n\n" + md_results(res, rules)
    (out / "r3_holdout.md").write_text(md, "utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
