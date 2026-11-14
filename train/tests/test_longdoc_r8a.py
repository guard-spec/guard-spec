# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of train/longdoc_r8a.py: the decision strong75_l2 and the stage guard (R8a, RF-35fd836c)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

try:
    import numpy as np  # noqa: E402
    import longdoc_r8a as R  # noqa: E402  (imports numpy through longdoc_r5)
    import verdict_r8a as V  # noqa: E402
except ImportError as e:  # the CI job without the training extras
    raise unittest.SkipTest(f"needs numpy (uv run): {e}")


def doc(n: int, p: float, l1: float, l2: float, at: int = 3) -> dict:
    """n windows of p = 0.1; window `at` has (p, l1, l2) and no floor."""
    d = {"p": np.full(n, 0.1), "l1": np.zeros(n), "l2": np.zeros(n), "f": np.zeros(n)}
    d["p"][at], d["l1"][at], d["l2"][at] = p, l1, l2
    return d


class Strong75L2(unittest.TestCase):
    def test_bar_value(self):
        self.assertEqual(R.L2_BAR, 0.95)
        self.assertEqual(R.DECISIONS[0], "strong75_l2")

    def test_long_text_needs_l2_bar(self):
        n = R.N0 + 10
        self.assertTrue(R.hits("strong75", R.N0, doc(n, 0.9, 0.99, 0.90)).any())
        self.assertFalse(R.hits("strong75_l2", R.N0, doc(n, 0.9, 0.99, 0.90)).any())
        self.assertTrue(R.hits("strong75_l2", R.N0, doc(n, 0.9, 0.99, 0.95)).any())

    def test_never_more_than_strong75(self):
        n = R.N0 + 10
        weak_l1 = doc(n, 0.9, 0.10, 0.99)  # no corroboration: strong75 does not block, neither does the bar
        self.assertFalse(R.hits("strong75", R.N0, weak_l1).any())
        self.assertFalse(R.hits("strong75_l2", R.N0, weak_l1).any())

    def test_short_text_keeps_base(self):
        short = doc(R.N0, 0.9, 0.0, 0.5)
        self.assertTrue(R.hits("strong75_l2", R.N0, short).any())

    def test_measure_uses_the_decision(self):
        n = R.N0 + 10
        b = dict(doc(n, 0.9, 0.99, 0.90), kind="benign", lang="en", tokens=100_000)
        m = R.L.measure("strong75_l2", R.N0, [b], [])
        self.assertEqual(m["benign"]["all"]["k"], 0)
        m = R.L.measure("strong75", R.N0, [b], [])
        self.assertEqual(m["benign"]["all"]["k"], 1)


class StageGuard(unittest.TestCase):
    def test_dev_refuses_holdouts(self):
        for p in ("x/long6/a", "x/long7/a", "x/long8/a"):
            with self.assertRaises(SystemExit):
                R.check_paths("dev", [p])
        R.check_paths("dev", ["x/dumps/E/benign"])

    def test_holdout_needs_long8(self):
        with self.assertRaises(SystemExit):
            R.check_paths("holdout", ["x/long7/E/benign"])
        R.check_paths("holdout", ["x/long8/E/benign"])


def longdoc(b100, b200, n=300, emb=0.90, alone=0.88):
    def cp(k):
        return list(R.L.clopper_pearson(k, n))
    s = {"blocked_100k": b100, "docs_100k": n, "cp95_100k": cp(b100), "blocked_200k": b200, "docs_200k": n,
         "cp95_200k": cp(b200), "embedded": emb, "alone": alone, "embedded_k": 0, "embedded_n": 0, "alone_k": 0, "alone_n": 0}
    return {"stage": "holdout", "decisions": ["strong75_l2"],
            "models": {"E": {"summary": {"strong75_l2": s}, "payload_clustered": {"strong75_l2": {}}}}}


def evalrep(tpr=0.95, fpr=0.008):
    return {"slices": {"holdout": {"at_fpr_1pct": {"tpr": tpr, "fpr": 0.0098}, "at_0.85": {"tpr": 0.94, "fpr": fpr}}}}


class Verdict(unittest.TestCase):
    def test_met_both(self):
        v = V.verdict(longdoc(0, 1), evalrep())
        self.assertTrue(v["set_a"]["met"])
        self.assertTrue(v["set_b"]["met"])

    def test_three_of_300_meets_both(self):
        v = V.verdict(longdoc(3, 0), evalrep())  # CP95 upper of 3 / 300 is 2.9%
        self.assertTrue(v["set_a"]["criteria"]["1"])
        self.assertTrue(v["set_b"]["criteria"]["1'"])

    def test_upper_bound_binds_on_small_samples(self):
        v = V.verdict(longdoc(1, 0, n=100), evalrep())  # 1 / 100 = 1%, CP95 upper 5.4%
        self.assertTrue(v["set_a"]["criteria"]["1"])
        self.assertFalse(v["set_b"]["criteria"]["1'"])

    def test_four_of_300_fails(self):
        self.assertFalse(V.verdict(longdoc(4, 0), evalrep())["set_a"]["met"])

    def test_detection_margin(self):
        self.assertTrue(V.verdict(longdoc(0, 0, emb=0.83, alone=0.88), evalrep())["set_a"]["criteria"]["2"])
        self.assertFalse(V.verdict(longdoc(0, 0, emb=0.82, alone=0.88), evalrep())["set_a"]["criteria"]["2"])

    def test_short_path(self):
        self.assertFalse(V.verdict(longdoc(0, 0), evalrep(tpr=0.94))["set_a"]["criteria"]["3"])
        v = V.verdict(longdoc(0, 0), evalrep(fpr=0.012))
        self.assertTrue(v["set_a"]["criteria"]["3"])
        self.assertFalse(v["set_b"]["criteria"]["3'"])


if __name__ == "__main__":
    unittest.main()
