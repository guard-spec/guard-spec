"""Shared helpers for train.py, export.py and evaluate.py."""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
import yaml
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parent  # train/


def load_config():
    return yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))


def seed_everything(seed: int):
    import torch
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f]


def label_matrix(rows, labels):
    y = np.zeros((len(rows), len(labels)), dtype=np.float32)
    for i, r in enumerate(rows):
        for lb in r["labels"]:
            y[i, labels.index(lb)] = 1.0
    return y


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def risk_scores(probs, labels, kind):
    """Overall attack-risk score from per-label probabilities."""
    if kind == "1-p_benign":
        return 1.0 - probs[:, labels.index("benign")]
    if kind == "max_attack":
        return probs[:, 1:].max(axis=1)
    raise ValueError(kind)


def auc(y, s):
    y = np.asarray(y)
    if y.min() == y.max():
        return float("nan")
    return float(roc_auc_score(y, s))


def threshold_at_fpr(neg_scores, target_fpr):
    """Smallest threshold t such that mean(neg >= t) <= target_fpr."""
    neg = np.sort(np.asarray(neg_scores, dtype=np.float64))[::-1]
    k = int(np.floor(target_fpr * len(neg)))  # number of negatives allowed at or above t
    if k >= len(neg):
        return float(neg[-1])
    # Any t strictly above neg[k] lets at most k negatives through.
    # Midpoint to the next higher negative, so the threshold survives float32 rounding in the runtime.
    if k > 0 and neg[k - 1] > neg[k]:
        return float((neg[k - 1] + neg[k]) / 2)
    return float(np.nextafter(np.float32(neg[k]), np.float32(np.inf)))


def rates(y, s, t):
    y = np.asarray(y).astype(bool)
    s = np.asarray(s, dtype=np.float64)  # NumPy 2 compares float32 arrays with Python floats in float32
    tpr = float((s[y] >= t).mean()) if y.any() else float("nan")
    fpr = float((s[~y] >= t).mean()) if (~y).any() else float("nan")
    return tpr, fpr


def tpr_at_fpr(y, s, target=0.01):
    y = np.asarray(y).astype(bool)
    s = np.asarray(s, dtype=np.float64)  # NumPy 2 compares float32 arrays with Python floats in float32
    t = threshold_at_fpr(s[~y], target)
    tpr, fpr = rates(y, s, t)
    return tpr, fpr, t
