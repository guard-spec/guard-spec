"""Tests of train/select_v6.py, the pre-registered v6 arm-selection rule (standard library only)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import select_v6 as S  # noqa: E402


def rows(file, benign, attack, kind="log_vi"):
    out = [dict(file=file, labels=["benign"], risk=s, kind=kind) for s in benign]
    out += [dict(file=file, labels=["jailbreak", "indirect_injection"], risk=s, kind="embedded") for s in attack]
    return out


def arm_scores(v6_benign_hi=0):
    ob = [i / 1000 for i in range(200)]
    return (rows("val", ob, [0.9] * 100) + rows("val_v6", [0.05] * (100 - v6_benign_hi) + [0.95] * v6_benign_hi, [0.9] * 50)
            + rows("val_v6_holdout", [0.99] * 10, [0.0] * 10))


def eval_rep(metric, fields, latency=5000.0):
    return {"slices": {"dev": {metric: fields}, "holdout": {metric: {k: 1.0 for k in fields}}},
            metric: {k: 1.0 for k in fields}, "latency": {"all": {"p50_us": latency}}}


def val_v3_rep(tpr):
    return {"groups": {"all": {"at_0.85": {"tpr": tpr, "fpr": 0.0}, "n_attack": 31}}, "slices": {"dev": {"at_0.85": {"tpr": 0.0}}}}


def bench_rep(fpr100=(0.0, 0.0), fpr200=(0.0, 0.0), prose_tpr=0.9, control_tpr=0.9, cap=True):
    """A benchlong report: dev cells of 3 EN / 4 VI documents per size and 15 EN / 17 VI payloads per
    variant; the holdout rows carry numbers that must never be read."""
    fprs = []
    for size, (en, vi) in zip(S.G6_SIZES, (fpr100, fpr200)):
        fprs += [dict(layer=S.BENCH_LAYER, split="dev", lang="en", size=size, docs=3, fpr=en, gateway_fpr=en),
                 dict(layer=S.BENCH_LAYER, split="dev", lang="vi", size=size, docs=4, fpr=vi, gateway_fpr=vi),
                 dict(layer=S.BENCH_LAYER, split="holdout", lang="en", size=size, docs=6, fpr=1.0, gateway_fpr=1.0),
                 dict(layer="l1/max", split="dev", lang="en", size=size, docs=3, fpr=1.0, gateway_fpr=1.0)]
    fprs.append(dict(layer=S.BENCH_LAYER, split="dev", lang="en", size="20k", docs=5, fpr=1.0, gateway_fpr=1.0))
    tprs = []
    pe, pv = prose_tpr if isinstance(prose_tpr, tuple) else (prose_tpr, prose_tpr)
    for v in S.G7_VARIANTS + ("control", "split_far", "hidden_tags"):
        te, tv = (control_tpr, control_tpr) if v == "control" else ((0.0, 0.0) if v == "split_far" else (pe, pv))
        tprs += [dict(layer=S.BENCH_LAYER, split="dev", lang="en", variant=v, docs=15, gateway_tpr=te, tpr_at_block=te),
                 dict(layer=S.BENCH_LAYER, split="dev", lang="vi", variant=v, docs=17, gateway_tpr=tv, tpr_at_block=tv),
                 dict(layer=S.BENCH_LAYER, split="holdout", lang="en", variant=v, docs=17, gateway_tpr=0.0, tpr_at_block=0.0)]
    return {"header": {"l2_cap": cap, "profile": "full"}, "score_pass": {"tokens_per_s": 6000.0, "cpu_s": 18000.0, "l2_windows": 49594},
            "doc_fpr_by_split": fprs, "tpr_by_split": tprs}


def reports(eval_tpr=0.94, codelog_fpr=0.02, emb_tpr=0.93, emb_fpr=0.04, val_v3_tpr=0.95, **bench):
    return dict(eval=eval_rep("at_fpr_1pct", {"tpr": eval_tpr}), codelog=eval_rep("at_0.85", {"fpr": codelog_fpr}),
                embedded=eval_rep("at_0.85", {"tpr": emb_tpr, "fpr": emb_fpr}), val_v3=val_v3_rep(val_v3_tpr),
                bench=bench_rep(**bench))


def refs():
    r = {"v3b": reports(eval_tpr=0.9086, codelog_fpr=0.2162, emb_tpr=0.8067, emb_fpr=0.105, val_v3_tpr=0.95)}
    r["l1"] = {"embedded": eval_rep("at_0.85", {"tpr": 0.8506, "fpr": 0.02})}
    return r


class Stats(unittest.TestCase):
    def test_clopper_pearson(self):
        self.assertAlmostEqual(S.clopper_pearson_upper(0, 15), 1 - 0.025 ** (1 / 15), places=6)  # 0.218
        self.assertAlmostEqual(S.clopper_pearson_upper(0, 1), 0.975, places=6)
        self.assertAlmostEqual(S.clopper_pearson_upper(1, 15), 0.3195, places=3)
        self.assertEqual(S.clopper_pearson_upper(15, 15), 1.0)

    def test_validation_metrics_ignore_holdout(self):
        m = S.validation_metrics(arm_scores(v6_benign_hi=3))
        self.assertEqual(m["orig"]["n_benign"], 200)
        self.assertEqual(m["val_v6"]["n_benign"], 100)  # val_v6_holdout rows are not read
        self.assertAlmostEqual(m["val_v6"]["fpr"], 0.03)
        self.assertLessEqual(m["orig"]["fpr"], 0.01)

    def test_bench_dev_only(self):
        b = bench_rep(fpr100=(1 / 3, 0.0), fpr200=(0.0, 0.25))
        blocked, docs, cells = S.bench_dev_fpr(b)
        self.assertEqual((blocked, docs), (2, 14))  # holdout rows, 20k and l1/max rows are not read
        self.assertEqual(cells["en/100k"], dict(blocked=1, docs=3))
        det, n = S.bench_dev_tpr(b, S.G7_VARIANTS)
        self.assertEqual(n, 7 * 32)
        self.assertEqual(S.bench_dev_tpr(b, ("control",))[1], 32)
        with self.assertRaises(SystemExit):
            S.bench_dev_fpr({"doc_fpr_by_split": []})


class Rule(unittest.TestCase):
    def test_gates_pass(self):
        g = S.gates_for("A", reports(), refs())
        self.assertEqual([k for k in g], ["G1", "G2", "G3", "G4", "G5", "G6", "G7"])
        self.assertTrue(all(x["ok"] for x in g.values()), {k: v["ok"] for k, v in g.items()})
        self.assertEqual((g["G6"]["blocked"], g["G6"]["docs"]), (0, 14))
        self.assertAlmostEqual(g["G6"]["cp95_upper"], 1 - 0.025 ** (1 / 14), places=6)

    def test_gates_fail_one_by_one(self):
        ref = refs()
        fails = dict(G1=dict(eval_tpr=0.90), G2=dict(codelog_fpr=0.031), G3=dict(emb_tpr=0.84), G4=dict(emb_fpr=0.11),
                     G5=dict(val_v3_tpr=0.93), G6=dict(fpr100=(1 / 3, 0.0)), G7=dict(prose_tpr=0.84, control_tpr=0.9))
        for gate, kw in fails.items():
            g = S.gates_for("A", reports(**kw), ref)
            self.assertEqual([k for k, v in g.items() if not v["ok"]], [gate], gate)
        # G5 margin: one point under v3b passes. G7 margin: payloads alone all caught, in prose 14/15 EN and
        # 17/17 VI per variant (0.969, within five points) passes, 13/15 and 16/17 (0.906) does not.
        g = S.gates_for("A", reports(val_v3_tpr=0.94, prose_tpr=(14 / 15, 1.0), control_tpr=1.0), ref)
        self.assertTrue(g["G5"]["ok"] and g["G7"]["ok"])
        self.assertEqual((g["G7"]["detected"], g["G7"]["docs"], g["G7"]["alone_detected"]), (217, 224, 32))
        g = S.gates_for("A", reports(prose_tpr=(13 / 15, 16 / 17), control_tpr=1.0), ref)
        self.assertFalse(g["G7"]["ok"])
        # G6 is about the 100k and 200k documents only.
        g = S.gates_for("A", reports(fpr200=(0.0, 0.25)), ref)
        self.assertFalse(g["G6"]["ok"])
        self.assertEqual(g["G6"]["blocked"], 1)

    def test_decide_ranks_passing_arms(self):
        ref = refs()
        gates = {"A": S.gates_for("A", reports(eval_tpr=0.94), ref),
                 "B": S.gates_for("B", reports(eval_tpr=0.95, codelog_fpr=0.05), ref),  # best G1 but fails G2
                 "C": S.gates_for("C", reports(eval_tpr=0.94, emb_tpr=0.95), ref)}      # ties A on G1, higher G3
        d = S.decide(["A", "B", "C"], gates)
        self.assertEqual((d["status"], d["chosen"], d["order"]), ("chosen", "C", ["C", "A"]))
        self.assertEqual(d["best_per_gate"]["G1"]["arm"], "B")
        # G6 breaks a G1 tie before G3: fewer blocked documents win.
        gates["A"]["G6"]["value"], gates["C"]["G6"]["value"] = 0.0, 0.01
        self.assertEqual(S.decide(["A", "B", "C"], gates)["chosen"], "A")
        # A difference in the fifth decimal of G1 is a tie.
        gates["C"]["G1"]["value"] = 0.94004
        self.assertEqual(S.decide(["A", "B", "C"], gates)["chosen"], "A")

    def test_decide_no_arm(self):
        ref = refs()
        gates = {"A": S.gates_for("A", reports(codelog_fpr=0.05), ref),
                 "B": S.gates_for("B", reports(eval_tpr=0.95, codelog_fpr=0.05, fpr100=(1 / 3, 0.0)), ref)}
        d = S.decide(["A", "B"], gates)
        self.assertEqual((d["status"], d["chosen"], d["fallback_candidate"]), ("no arm qualifies", None, "A"))
        self.assertEqual(d["gates_met"], dict(A=6, B=5))
        self.assertEqual(d["best_per_gate"]["G1"], dict(arm="B", value=0.95, ok=True))
        self.assertEqual(d["best_per_gate"]["G6"]["arm"], "A")
        self.assertEqual(S.decide(["A"], None)["status"], "gates pending")

    def test_main_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for a in ("A", "B"):
                (d / a).mkdir()
                (d / a / "val_scores.jsonl").write_text("".join(json.dumps(r) + "\n" for r in arm_scores()))
                log = dict(best_epoch=2, train_seconds=600, n_train_rows=10, n_train=12, n_val=5,
                           epochs=[dict(epoch=1, val_loss=0.1), dict(epoch=2, val_loss=0.05)],
                           config=dict(seed=1, train={}, data=dict(train_files=["/x/train.jsonl"])))
                (d / a / "train_log.json").write_text(json.dumps(log))
            gd = d / "gates"
            reps = dict(A=reports(eval_tpr=0.94), B=reports(eval_tpr=0.95, emb_tpr=0.80), v3b=refs()["v3b"])
            for n, r in reps.items():
                (gd / n).mkdir(parents=True)
                for k, v in r.items():
                    (gd / n / ("benchlong-full.json" if k == "bench" else f"{k}.json")).write_text(json.dumps(v))
            (gd / "l1").mkdir()
            (gd / "l1" / "embedded.json").write_text(json.dumps(refs()["l1"]["embedded"]))
            out = d / "report.json"
            rep = S.main(["--arm", f"A={d / 'A'}", "--arm", f"B={d / 'B'}", "--gates", str(gd), "--out", str(out)])
            self.assertEqual(rep["decision"]["chosen"], "A")  # B fails G3
            self.assertEqual(rep["arms"]["A"]["recorded"]["eval_latency_p50_us"]["ratio"], 1.0)
            self.assertTrue(rep["arms"]["A"]["recorded"]["bench_l2_cap"])
            self.assertTrue(out.exists())
            rep = S.main(["--arm", f"A={d / 'A'}", "--gates", str(d / "nothing"), "--out", str(out)])
            self.assertEqual(rep["decision"]["status"], "gates pending")
            self.assertTrue(rep["gates_missing"])


if __name__ == "__main__":
    unittest.main()
