# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of the R8e data and verdict (RF-943afc53; no network, no data files): the templates of T+, O+, N+, tp1,
vi1 and the long11 payloads, the `long11` profile and its sources, and train/verdict_r8e.py on synthetic summaries.

    cd train && uv run --frozen python -m unittest tests/test_r8e.py -v
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(TRAIN / "data"))
sys.path.insert(0, str(TRAIN))

import r8e_templates as T  # noqa: E402
import verdict_r8e as V  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

SEED = 20261122
LABELS = {"benign", "direct_injection", "indirect_injection", "jailbreak", "prompt_extraction", "data_exfiltration",
          "tool_poisoning", "obfuscation"}


def norm(t):
    return re.sub(r"\s+", " ", t.lower()).strip()


class TemplatesTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(T.no_diacritics("Đưa toàn bộ lịch sử"), "Dua toan bo lich su")
        t = T.teencode("Không được phép gửi cho người khác")
        self.assertNotRegex(t, r"[à-ỹđ]")
        self.assertIn("ko", t)

    def test_tplus(self):
        rows = T.t_rows(SEED, 600, 600)
        self.assertEqual(rows, T.t_rows(SEED, 600, 600))
        self.assertEqual(len(rows), 1200)
        self.assertEqual(len({r["text"] for r in rows}), 1200)
        for r in rows:
            json.loads(r["text"])
            self.assertTrue(set(r["labels"]) <= LABELS)
            if r["kind"] == "r8e_tplus_attack":
                self.assertIn("tool_poisoning", r["labels"])
            else:
                self.assertEqual(r["labels"], ["benign"])
        self.assertEqual({r["variant"] for r in rows if r["lang"] == "vi"}, {"orig", "no_diacritics", "teencode"})

    def test_oplus_nplus(self):
        o = T.o_rows(SEED, 400)
        n = T.n_rows(SEED, 280)
        self.assertEqual((len(o), len(n)), (400, 280))
        self.assertTrue(all(r["labels"] == ["direct_injection"] for r in o))
        self.assertTrue(all(r["labels"] == ["benign"] for r in n))
        for r in o:  # paraphrased: no "ignore" / "bỏ qua"
            self.assertNotRegex(r["text"].lower(), r"\bignore\b|bỏ qua|bo qua")
        self.assertEqual({r["variant"] for r in n if r["lang"] == "vi"}, {"no_diacritics", "teencode"})

    def test_holdout_inventories_are_separate(self):
        """tp1 and the long11 payloads share no tool name, field or sentence frame with T+."""
        tr = {t[0] for t in T.T_TOOLS_EN + T.T_TOOLS_VI}
        ho = {t[0] for t in T.TP_TOOLS_EN + T.TP_TOOLS_VI}
        l11 = {json.loads(p)["name"] for _, p in T.LONG11_PAYLOADS}
        self.assertFalse(tr & ho)
        self.assertFalse(tr & l11)
        self.assertFalse(set(T.T_FIELDS) & set(T.TP_FIELDS))
        frames = {norm(x) for x in T.T_ATK_EN + T.T_ATK_VI + T.T_BEN_EN + T.T_BEN_VI}
        self.assertFalse(frames & {norm(x) for x in T.TP_ATK_EN + T.TP_ATK_VI + T.TP_BEN_EN + T.TP_BEN_VI})

    def test_tp1_vi1(self):
        tp = T.tp1_rows(SEED)
        self.assertEqual(len(tp), 300)
        self.assertEqual(sum(r["label"] == "attack" for r in tp), 150)
        v = T.vi1_template_rows(SEED, 300)
        self.assertEqual(len(v), 300)
        self.assertEqual({r["variant"] for r in v}, {"orig", "no_diacritics", "teencode"})
        self.assertEqual(len(T.LONG11_PAYLOADS), 12)


class SourcesTest(unittest.TestCase):
    def setUp(self):
        if yaml is None:
            self.skipTest("needs PyYAML (uv run)")
        self.corpus = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
        self.prof = self.corpus["profiles"]["long11"]

    def test_long11(self):
        self.assertEqual(self.prof["id_prefix"], "long11-")
        self.assertRegex(self.corpus["outputs"]["long11"], r"^[0-9a-f]{64}$")
        for n, p in self.corpus["profiles"].items():
            if n != "long11":
                self.assertFalse(set(self.prof["sources"]) & set(p.get("sources") or self.corpus["sources"]), n)
        for name in self.prof["sources"]:
            src = self.corpus["sources"][name]
            self.assertRegex(src.get("sha256") or "", r"^[0-9a-f]{64}$", name)

    def test_disjoint(self):
        mine = [self.corpus["sources"][n] for n in self.prof["sources"]]
        others = [s for n, s in self.corpus["sources"].items() if n not in self.prof["sources"]]
        for f in sorted((TRAIN / "data").glob("sources_*.yaml")):
            others += list((yaml.safe_load(f.read_text("utf-8")).get("sources") or {}).values())
        repos = lambda ss: {s["repo"] for s in ss if s.get("kind") == "github-tree"}  # noqa: E731
        rfcs = lambda ss: {p for s in ss if s.get("genre") == "rfc" for p in s.get("paths", [])}  # noqa: E731
        self.assertFalse(repos(mine) & repos(others))
        self.assertTrue(rfcs(mine))
        self.assertFalse(rfcs(mine) & rfcs(others))


def f(k, n):
    return {"k": k, "n": n, "rate": k / n, "cp95_upper": 0}


def summ(vi1, tpv, tpf, l11e, l11b, p3=(1, 1), s2=(50, 1), c2=0.95):
    return {"vi1": {"all": f(vi1, 862)}, "tp1": {"vi": {"tpr": f(tpv, 86)}, "all": {"fpr": f(tpf, 150)}},
            "long11": {"embedded_caught": f(l11e, 252), "benign_blocked": f(l11b, 50)},
            "persona3": {"by_lang": {"en": f(p3[0], 396), "vi": f(p3[1], 117)}},
            "split2": {"all": {"tpr": f(s2[0], 60), "fpr": f(s2[1], 60)}}, "eval_data_holdout": {"tpr_at_fpr1": c2}}


class VerdictTest(unittest.TestCase):
    def run_it(self, S):
        with tempfile.TemporaryDirectory() as d:
            for n, s in S.items():
                (Path(d) / n).mkdir()
                (Path(d) / n / "summary.json").write_text(json.dumps(s))
            out = Path(d) / "v.json"
            V.verdict(argparse.Namespace(measure=[d], out=str(out)))
            return json.loads(out.read_text())

    def test_bars_and_decision(self):
        S = {"v8e": summ(3, 80, 2, 200, 3), "E-s2": summ(9, 70, 2, 190, 4), "E-s3": summ(12, 72, 3, 195, 5),
             "EPL2-s1": summ(6, 74, 2, 185, 2), "EPL2-s2": summ(5, 76, 2, 188, 3), "EPL2-s3": summ(8, 70, 2, 180, 1)}
        good = summ(5, 82, 2, 196, 2)
        S.update({"EPL3-s1": good, "EPL3-s2": summ(4, 83, 3, 198, 3, c2=0.97), "EPL3-s3": good})
        r = self.run_it(S)
        self.assertAlmostEqual(r["bars"]["R1_vi1_benign_blocked_max"], 8 / 862)
        self.assertAlmostEqual(r["bars"]["R2_tp1_vi_tpr_min"], 76 / 86 + 0.05)
        self.assertAlmostEqual(r["bars"]["R3_long11_embedded_min"], 200 / 252 - 0.02)
        self.assertEqual(r["bars"]["R3_long11_benign_blocked_max"], 3)
        self.assertTrue(r["decision"]["all_seeds_pass"])
        self.assertEqual(r["decision"]["candidate"], "EPL3-s2")
        S["EPL3-s3"] = summ(9, 82, 2, 196, 2)  # more vi1 blocks than v8g
        r = self.run_it(S)
        self.assertEqual(r["decision"]["failed"], {"EPL3-s3": ["R1"]})
        self.assertEqual(r["decision"]["candidate"], "v8g (EPL2-s3)")


if __name__ == "__main__":
    unittest.main()
