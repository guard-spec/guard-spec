"""Tests of train/select_v5.py, the pre-registered v5 arm-selection rule (standard library only)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import select_v5 as S  # noqa: E402


def rows(file, benign, attack, kind="log_vi", position="comment"):
    out = [dict(file=file, labels=["benign"], risk=s, kind=kind) for s in benign]
    out += [dict(file=file, labels=["jailbreak", "indirect_injection"], risk=s, kind="embedded", position=position)
            for s in attack]
    return out


def arm_scores(v5_benign_hi=0, v5_attack_lo=0, orig_attack_lo=0):
    """200 original benign rows (risk 0.0..0.199) + 100 attacks; val_v5 100 benign + 50 attacks.
    *_hi / *_lo move that many rows to the wrong side of every threshold."""
    ob = [i / 1000 for i in range(200)]
    oa = [0.9] * (100 - orig_attack_lo) + [0.01] * orig_attack_lo
    vb = [0.05] * (100 - v5_benign_hi) + [0.95] * v5_benign_hi
    va = [0.9] * (50 - v5_attack_lo) + [0.01] * v5_attack_lo
    return rows("val", ob, oa) + rows("val_v5", vb, va) + rows("val_v5_holdout", [0.99] * 10, [0.0] * 10)


class Metrics(unittest.TestCase):
    def test_threshold_and_auc(self):
        neg = [i / 100 for i in range(100)]
        t = S.threshold_at_fpr(neg, 0.01)
        self.assertAlmostEqual(S.rate(neg, t), 0.01)
        self.assertEqual(S.auc([1, 2], [0, 0.5]), 1.0)
        self.assertEqual(S.auc([0.5], [0.5]), 0.5)
        self.assertAlmostEqual(S.auc([0.1, 0.9], [0.5]), 0.5)

    def test_validation_metrics_ignore_holdout(self):
        m = S.validation_metrics(arm_scores(v5_benign_hi=3, v5_attack_lo=5))
        self.assertEqual(m["orig"]["n_benign"], 200)
        self.assertEqual(m["val_v5"]["n_benign"], 100)  # val_v5_holdout rows are not read
        self.assertAlmostEqual(m["val_v5"]["fpr"], 0.03)
        self.assertAlmostEqual(m["val_v5"]["tpr"], 0.9)
        self.assertAlmostEqual(m["val_v5"]["tpr_minus_fpr"], 0.87)
        self.assertLessEqual(m["orig"]["fpr"], 0.01)


class Rule(unittest.TestCase):
    def val(self, **arms):
        out = {}
        for a, kw in arms.items():
            out[a] = S.validation_metrics(arm_scores(**kw))
            out[a]["val_loss"] = 0.05
        return out

    def test_rank_on_val_v5_and_q1(self):
        val = self.val(A=dict(v5_benign_hi=10), B=dict(v5_benign_hi=2), C=dict(v5_benign_hi=0, orig_attack_lo=5))
        order, q1 = S.rank_arms(val)
        self.assertEqual(q1, dict(A=True, B=True, C=False))  # C loses 0.05 TPR on the original validation
        self.assertEqual(order, ["B", "A", "C"])

    def test_tie_breaks(self):
        val = self.val(A=dict(v5_benign_hi=1), B=dict(v5_benign_hi=1, orig_attack_lo=1))
        order, _ = S.rank_arms(val)
        self.assertEqual(order, ["A", "B"])  # same val_v5 score: higher original TPR first
        val["A"]["val_loss"], val["B"]["val_loss"] = 0.06, 0.04
        val["B"] = S.validation_metrics(arm_scores(v5_benign_hi=1))
        val["B"]["val_loss"] = 0.04
        order, _ = S.rank_arms(val)
        self.assertEqual(order, ["B", "A"])  # then lower validation loss

    def gate_reports(self, eval_tpr, codelog_fpr, emb_tpr):
        def rep(metric, field, v):
            return {"slices": {"dev": {metric: {field: v}}, "holdout": {metric: {field: 1.0}}}}
        return dict(eval=rep("at_fpr_1pct", "tpr", eval_tpr), codelog=rep("at_0.85", "fpr", codelog_fpr),
                    embedded=rep("at_0.85", "tpr", emb_tpr))

    def refs(self):
        r = {"v3b": self.gate_reports(0.93, 0.10, 0.807)}
        r["l1"] = {"embedded": self.gate_reports(0, 0, 0.851)["embedded"]}
        return r

    def test_gates(self):
        ref = self.refs()
        g = S.gates_for("A", self.gate_reports(0.94, 0.02, 0.86), ref)
        self.assertTrue(all(x["ok"] for x in g.values()))
        g = S.gates_for("A", self.gate_reports(0.92, 0.031, 0.83), ref)
        self.assertEqual([g[k]["ok"] for k in ("G1", "G2", "G3")], [False, False, False])  # 0.83 < L1's 0.851

    def test_decide(self):
        ref = self.refs()
        order, q1 = ["B", "A", "C"], dict(A=True, B=True, C=False)
        gates = {"A": S.gates_for("A", self.gate_reports(0.94, 0.02, 0.86), ref),
                 "B": S.gates_for("B", self.gate_reports(0.94, 0.05, 0.86), ref),
                 "C": S.gates_for("C", self.gate_reports(0.95, 0.01, 0.90), ref)}
        d = S.decide(order, q1, gates)
        self.assertEqual((d["status"], d["chosen"]), ("chosen", "A"))  # B fails G2, C fails Q1
        gates["A"]["G3"]["ok"] = False
        d = S.decide(order, q1, gates)
        self.assertEqual((d["status"], d["chosen"], d["shadow_candidate"]), ("no arm qualifies", None, "B"))
        self.assertEqual(S.decide(order, q1, None)["status"], "gates pending")

    def test_report_without_slices_is_an_error(self):
        with self.assertRaises(SystemExit):
            S.dev({"groups": {}}, "at_0.85", "tpr")

    def test_main_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for a, kw in dict(A=dict(v5_benign_hi=4), B=dict(v5_benign_hi=1)).items():
                (d / a).mkdir()
                (d / a / "val_scores.jsonl").write_text("".join(json.dumps(r) + "\n" for r in arm_scores(**kw)))
                log = dict(best_epoch=2, train_seconds=600, n_train_rows=10, n_train=12, n_val=5,
                           epochs=[dict(epoch=1, val_loss=0.1), dict(epoch=2, val_loss=0.05)],
                           config=dict(train={}, data=dict(train_files=["/x/train.jsonl"])))
                (d / a / "train_log.json").write_text(json.dumps(log))
            gd = d / "gates"
            for n, vals in dict(A=(0.94, 0.02, 0.86), B=(0.94, 0.02, 0.80), v3b=(0.93, 0.10, 0.807)).items():
                (gd / n).mkdir(parents=True)
                for k, v in self.gate_reports(*vals).items():
                    (gd / n / f"{k}.json").write_text(json.dumps(v))
            (gd / "l1").mkdir()
            (gd / "l1" / "embedded.json").write_text(json.dumps(self.gate_reports(0, 0, 0.851)["embedded"]))
            out = d / "report.json"
            rep = S.main(["--arm", f"A={d / 'A'}", "--arm", f"B={d / 'B'}", "--gates", str(gd), "--out", str(out)])
            self.assertEqual(rep["decision"]["validation_order"], ["B", "A"])
            self.assertEqual(rep["decision"]["chosen"], "A")  # B fails G3
            self.assertTrue(out.exists())
            rep = S.main(["--arm", f"A={d / 'A'}", "--gates", str(d / "nothing"), "--out", str(out)])
            self.assertEqual(rep["decision"]["status"], "gates pending")
            self.assertTrue(rep["gates_missing"])


if __name__ == "__main__":
    unittest.main()
