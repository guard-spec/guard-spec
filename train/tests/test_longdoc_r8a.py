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


if __name__ == "__main__":
    unittest.main()
