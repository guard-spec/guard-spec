# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of train/select_v8.py (the pre-registered v8 rule) and the stage guard of train/longdoc_v8.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

try:
    import longdoc_v8 as LD  # noqa: E402  (imports numpy through longdoc_r5)
    import select_v8 as S  # noqa: E402
except ImportError as e:  # the CI job without the training extras
    raise unittest.SkipTest(f"needs numpy (uv run): {e}")
from test_select_v6 import refs, reports  # noqa: E402

N_ATTACK = 600


def arm(**kw):
    r = reports(**kw)
    r["eval"]["slices"]["dev"]["n_attack"] = N_ATTACK
    return r


def summary(blocked, embedded, alone=0.875, docs=150):
    s = dict(blocked=blocked, docs=docs, cp95=[0.0, 0.1], embedded=embedded, alone=alone)
    return {"summary": {"strong75": s, "base": dict(s, blocked=blocked + 2)}}


def longdoc(**models):
    return {"stage": "dev", "decisions": ["strong75", "base"], "models": {n: summary(*v) for n, v in models.items()}}


def all_reps(**arms):
    reps = dict(refs())
    reps.update(arms)
    return reps


class Gates(unittest.TestCase):
    def test_gate_names_and_pass(self):
        reps = all_reps(ref=arm(eval_tpr=0.947), D=arm(eval_tpr=0.94))
        g = S.gates_v8("D", reps, longdoc(ref=(13, 0.87), D=(1, 0.85)))
        self.assertEqual(list(g), ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "LD-TPR", "LD-REF"])
        self.assertTrue(all(x["ok"] for x in g.values()), {k: v["ok"] for k, v in g.items()})
        self.assertLess(g["G8"]["ref_cp95_low"], 0.947)

    def test_gate_failures(self):
        reps = all_reps(ref=arm(eval_tpr=0.947), D=arm(eval_tpr=0.91))
        g = S.gates_v8("D", reps, longdoc(ref=(13, 0.87), D=(13, 0.80)))
        self.assertEqual([k for k, v in g.items() if not v["ok"]], ["G8", "LD-TPR", "LD-REF"])
        # LD-TPR margin: exactly alone - 5 points passes.
        g = S.gates_v8("D", reps, longdoc(ref=(13, 0.87), D=(0, 0.825)))
        self.assertTrue(g["LD-TPR"]["ok"])


class Decide(unittest.TestCase):
    def setUp(self):
        self.reps = all_reps(ref=arm(eval_tpr=0.947), D=arm(eval_tpr=0.94), E=arm(eval_tpr=0.945))

    def gates(self, ld):
        return {n: S.gates_v8(n, self.reps, ld) for n in ("D", "E", "ref")}

    def test_fewest_blocked_then_embedded(self):
        ld = longdoc(ref=(13, 0.87), D=(1, 0.86), E=(0, 0.84))
        d = S.decide(["D", "E"], self.gates(ld), ld)
        self.assertEqual((d["status"], d["chosen"], d["order"]), ("chosen", "E", ["E", "D"]))
        self.assertEqual((d["target"]["met"], d["target"]["limit"]), (True, 1))
        ld = longdoc(ref=(13, 0.87), D=(1, 0.86), E=(1, 0.84))
        self.assertEqual(S.decide(["D", "E"], self.gates(ld), ld)["chosen"], "D")
        ld = longdoc(ref=(13, 0.87), D=(1, 0.86), E=(1, 0.86))  # tie on long5: higher G1
        self.assertEqual(S.decide(["D", "E"], self.gates(ld), ld)["chosen"], "E")

    def test_no_arm_fallback(self):
        ld = longdoc(ref=(13, 0.87), D=(0, 0.80), E=(14, 0.86))  # D fails LD-TPR, E fails LD-REF
        d = S.decide(["D", "E"], self.gates(ld), ld)
        self.assertEqual((d["status"], d["chosen"], d["fallback_candidate"]), ("no arm qualifies", None, "D"))
        self.assertIn("long7", d["note"])


class Main(unittest.TestCase):
    def test_end_to_end_and_dev_only(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            gd = d / "gates"
            reps = dict(ref=arm(eval_tpr=0.947), D=arm(eval_tpr=0.94), E=arm(eval_tpr=0.945), v3b=refs()["v3b"])
            for n, r in reps.items():
                (gd / n).mkdir(parents=True)
                for k, v in r.items():
                    (gd / n / ("benchlong-full.json" if k == "bench" else f"{k}.json")).write_text(json.dumps(v))
            (gd / "l1").mkdir()
            (gd / "l1" / "embedded.json").write_text(json.dumps(refs()["l1"]["embedded"]))
            ld = longdoc(ref=(13, 0.87), D=(0, 0.86), E=(0, 0.85), v6rel=(9, 0.88))
            lp = d / "v8_dev_longdoc.json"
            lp.write_text(json.dumps(ld))
            out = d / "v8_dev.json"
            rep = S.main(["--arms", "D,E", "--gates", str(gd), "--longdoc", str(lp), "--out", str(out)])
            self.assertEqual(rep["decision"]["chosen"], "D")
            self.assertIn("v6rel", rep["also_measured"])
            self.assertTrue(out.exists())
            lp.write_text(json.dumps(dict(ld, stage="holdout")))
            with self.assertRaises(SystemExit):
                S.main(["--arms", "D,E", "--gates", str(gd), "--longdoc", str(lp), "--out", str(out)])


class StageGuard(unittest.TestCase):
    def test_paths(self):
        LD.check_paths("dev", ["/w/dumps/D/benign", "/w/dumps/D/attack"])
        for p in ("/w/holdout/D/long7-benign", "/x/long6/attack"):
            with self.assertRaises(SystemExit):
                LD.check_paths("dev", [p])
        LD.check_paths("holdout", ["/w/long7/D/benign"])
        with self.assertRaises(SystemExit):
            LD.check_paths("holdout", ["/w/dumps/D/benign"])


if __name__ == "__main__":
    unittest.main()
