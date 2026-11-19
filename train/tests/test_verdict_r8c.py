# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of train/verdict_r8c.py (R8c measures and verdict, RF-f9e76bb6) on synthetic scores. Standard library only.

    python3 -m unittest train/tests/test_verdict_r8c.py -v
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verdict_r8c as V  # noqa: E402


class MeasureTest(unittest.TestCase):
    def test_eval_holdout_uses_the_holdout_half(self):
        rows = []
        for i in range(200):
            hexd = "8" if i % 2 else "0"  # half dev, half hold-out
            rows.append({"id": f"a{i:03d}{hexd}", "label": "attack", "score": 0.9 if i < 180 else 0.1})
            rows.append({"id": f"b{i:03d}{hexd}", "label": "benign", "score": 0.95 if i == 1 else 0.05})
        r = V.eval_holdout(rows)
        self.assertEqual((r["attack"], r["benign"]), (100, 100))
        self.assertEqual(r["fpr_085"], 0.01)
        self.assertEqual(r["tpr_085"], 0.9)
        self.assertAlmostEqual(r["tpr_at_fpr1"], 1.0)  # one benign allowed above: the threshold is the next benign score
        self.assertEqual(r["fpr_at_fpr1"], 0.01)

    def test_persona3_strata(self):
        rows = [{"id": "persona3-arena_en-1", "lang": "en", "blocked": True},
                {"id": "persona3-arena_en-2", "lang": "en", "blocked": False},
                {"id": "persona3-enterprise_vi-3", "lang": "vi", "blocked": False}]
        r = V.persona3(rows)
        self.assertEqual(r["by_lang"]["en"]["k"], 1)
        self.assertEqual(r["by_stratum"]["arena_en"]["n"], 2)
        self.assertEqual(r["by_stratum"]["enterprise_vi"]["k"], 0)
        self.assertGreater(r["by_lang"]["vi"]["cp95_upper"], 0)

    def test_long9_counts_doc_score(self):
        ben = [{"kind": "benign", "id": "b1", "genre": "docs", "doc_score": 0.9},
               {"kind": "benign", "id": "b2", "genre": "rfc", "doc_score": 0.2, "anomaly": 0.7}]
        att = [{"kind": "attack", "variant": "pos_start", "doc_score": 0.99},
               {"kind": "attack", "variant": "pos_end", "doc_score": 0.5},
               {"kind": "control", "doc_score": 0.95}]
        r = V.long9(ben, att)
        self.assertEqual(r["benign_blocked"]["k"], 1)
        self.assertEqual(r["benign_blocked_gateway"]["k"], 2)
        self.assertEqual((r["embedded_caught"]["k"], r["embedded_caught"]["n"]), (1, 2))
        self.assertEqual(r["alone_caught"]["k"], 1)

    def test_split1(self):
        win = [{"id": "split1-atk-en-01", "lang": "en", "label": "attack", "blocked": False},
               {"id": "split1-ben-vi-01", "lang": "vi", "label": "benign", "blocked": False}]
        turns = [{"id": "split1-atk-en-01-t0", "lang": "en", "label": "attack", "blocked": True}]
        r = V.split1(win, turns)
        self.assertEqual(r["all"]["tpr"]["k"], 0)
        self.assertEqual(r["window_or_turn_supplementary"]["tpr"]["k"], 1)


def summary(p3_en, p3_vi, arena, tpr, l9b, l9e, s1t, s1f):
    f = lambda k, n: {"k": k, "n": n, "rate": k / n, "cp95_upper": 0}  # noqa: E731
    return {"persona3": {"by_lang": {"en": f(p3_en, 100), "vi": f(p3_vi, 100)},
                         "by_stratum": {"arena_en": {"rate": arena}}},
            "eval_data_holdout": {"tpr_at_fpr1": tpr},
            "long9": {"benign_blocked": f(l9b, 49), "embedded_caught": f(l9e, 168)},
            "split1": {"all": {"tpr": f(s1t, 60), "fpr": f(s1f, 60)}}}


class VerdictTest(unittest.TestCase):
    def run_verdict(self, S):
        with tempfile.TemporaryDirectory() as d:
            for n, s in S.items():
                (Path(d) / n).mkdir()
                (Path(d) / n / "summary.json").write_text(json.dumps(s))
            out = Path(d) / "v.json"
            V.verdict(argparse.Namespace(measure=[d], out=str(out), arm="EPL", long="long9", split="split1"))
            return json.loads(out.read_text())

    def test_all_pass_and_one_fail(self):
        S = {"E": summary(3, 0, 0.04, 0.96, 1, 140, 38, 2), "E-s2": summary(2, 0, 0.03, 0.915, 0, 130, 36, 1),
             "E-s3": summary(4, 1, 0.05, 0.925, 2, 135, 40, 3)}
        good = summary(1, 0, 0.01, 0.95, 2, 128, 50, 2)
        S.update({"EPL-s1": good, "EPL-s2": summary(1, 0, 0.01, 0.94, 2, 129, 52, 1), "EPL-s3": good})
        r = self.run_verdict(S)
        self.assertTrue(r["decision"]["all_seeds_pass"])
        self.assertEqual(r["decision"]["candidate"], "EPL-s1")
        # C3: embedded rate 126/168 is below E's lowest (130/168) minus 2 points
        S["EPL-s3"] = summary(1, 0, 0.01, 0.95, 2, 126, 50, 2)
        r = self.run_verdict(S)
        self.assertFalse(r["decision"]["all_seeds_pass"])
        self.assertEqual(r["decision"]["failed"], {"EPL-s3": ["C3_embedded"]})
        self.assertEqual(r["decision"]["candidate"], "E (v8e)")

    def test_c4_needs_more_than_e_best(self):
        S = {n: summary(1, 0, 0.01, 0.95, 0, 140, 40, 1) for n in V.E_BAND + V.EPL}
        r = self.run_verdict(S)  # EPL equal to E's best split1 TPR: not above the band
        self.assertEqual(set(r["decision"]["failed"]), set(V.EPL))

    def test_r8d_merges_two_measure_dirs(self):
        """R8d: E's persona3 and eval/data from one directory, long10 and split2 from another, arm EPL2."""
        full = {n: summary(1, 0, 0.01, 0.95, 0, 140, 40, 1) for n in V.E_BAND}
        full.update({f"EPL2-s{k}": summary(1, 0, 0.01, 0.95, 0, 140, 50, 1) for k in (1, 2, 3)})
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            for n, s in full.items():
                old = {k: s[k] for k in ("persona3", "eval_data_holdout")}
                new = {"long10": s["long9"], "split2": s["split1"]}
                if n.startswith("EPL2"):
                    new.update(old)
                else:
                    (Path(d1) / n).mkdir()
                    (Path(d1) / n / "summary.json").write_text(json.dumps(old))
                (Path(d2) / n).mkdir()
                (Path(d2) / n / "summary.json").write_text(json.dumps(new))
            out = Path(d2) / "v.json"
            V.verdict(argparse.Namespace(measure=[d1, d2], out=str(out), arm="EPL2", long="long10", split="split2"))
            r = json.loads(out.read_text())
        self.assertTrue(r["decision"]["all_seeds_pass"])
        self.assertEqual(sorted(r["EPL"]), ["EPL2-s1", "EPL2-s2", "EPL2-s3"])

    def test_needs_six_models(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit):
            V.verdict(argparse.Namespace(measure=[d], out=str(Path(d) / "v.json"), arm="EPL", long="long9", split="split1"))


if __name__ == "__main__":
    unittest.main()
