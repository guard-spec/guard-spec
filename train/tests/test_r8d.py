# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of the R8d data (RF-e82b0347; no network, no data files): the templates of N and split2, the `long10`
profile of bench/long/corpus.yaml and the sources of data/sources_r8d.yaml.

    cd train && uv run --frozen python -m unittest tests/test_r8d.py -v

Parts that need PyYAML are skipped without it.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(TRAIN / "data"))

import r8c_templates as T8C  # noqa: E402
import r8d_templates as T  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

SEED = 20261120


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower()).strip()


def sentences(texts) -> set[str]:
    out = set()
    for t in texts:
        out |= {norm(x) for x in re.split(r"(?<=[.?!])\s+", t) if len(x.split()) >= 4}
    return out


def frozen_texts() -> list[str]:
    d = json.loads((REPO / "cmd/gateway/testdata/multiturn.json").read_text("utf-8"))
    out = [t for c in d["conversations"] for t in c["turns"]]
    out += re.findall(r"`([^`]*)`", (REPO / "internal/inference/rules/payload_split_test.go").read_text("utf-8"))
    return out


def r8c_texts() -> list[str]:
    out = [t for c in T8C.split1_conversations(20261119) for t in c["turns"]]
    return out + [r["text"] for r in T8C.s_rows(20261119, 400, 400, 0.5)]


class Split2Test(unittest.TestCase):
    def test_shape_counts_seeded(self):
        cs = T.split2_conversations(SEED)
        self.assertEqual(cs, T.split2_conversations(SEED))
        self.assertEqual(len(cs), 120)
        self.assertEqual(len({c["id"] for c in cs}), 120)
        self.assertEqual(len({tuple(c["turns"]) for c in cs}), 120)
        for lang in ("en", "vi"):
            for kind in ("attack", "benign"):
                self.assertEqual(sum(1 for c in cs if c["lang"] == lang and c["kind"] == kind), 30)
            self.assertGreaterEqual(sum(1 for c in cs if c["lang"] == lang and c.get("pattern") == "negated"), 10)
        self.assertTrue(all(2 <= len(c["turns"]) <= 4 for c in cs))

    def test_no_shared_sentence(self):
        mine = sentences(t for c in T.split2_conversations(SEED) for t in c["turns"])
        self.assertFalse(mine & sentences(frozen_texts()))
        self.assertFalse(mine & sentences(r8c_texts()))
        self.assertFalse(mine & sentences(r["text"] for r in T.n_rows(SEED, 400, 0.5)))


class NTest(unittest.TestCase):
    def test_counts_labels_seeded(self):
        rows = T.n_rows(SEED, 400, 0.5)
        self.assertEqual(rows, T.n_rows(SEED, 400, 0.5))
        self.assertEqual(len(rows), 400)
        self.assertEqual(len({r["text"] for r in rows}), 400)
        self.assertTrue(all(r["labels"] == ["benign"] for r in rows))
        for lang in ("en", "vi"):
            self.assertEqual(sum(1 for r in rows if r["lang"] == lang), 200)
        self.assertEqual({r["kind"] for r in rows}, {"r8d_neg_negated", "r8d_neg_quoted", "r8d_neg_split"})

    def test_no_shared_sentence(self):
        mine = sentences(r["text"] for r in T.n_rows(SEED, 400, 0.5))
        self.assertFalse(mine & sentences(frozen_texts()))
        self.assertFalse(mine & sentences(r8c_texts()))

    def test_reject(self):
        rows = T.n_rows(SEED, 20, 0.5, reject=lambda t: "quiz" in t)
        self.assertFalse(any("quiz" in r["text"] for r in rows))


class SourcesTest(unittest.TestCase):
    def setUp(self):
        if yaml is None:
            self.skipTest("needs PyYAML (uv run)")
        self.corpus = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
        self.r8d = yaml.safe_load((TRAIN / "data/sources_r8d.yaml").read_text("utf-8"))
        self.prof = self.corpus["profiles"]["long10"]

    def test_long10_profile(self):
        self.assertEqual(self.prof["id_prefix"], "long10-")
        self.assertEqual(self.prof["payloads_per_lang"], 0)
        self.assertEqual(self.prof["synthetic"], [])
        self.assertRegex(self.corpus["outputs"]["long10"], r"^[0-9a-f]{64}$")
        for n, p in self.corpus["profiles"].items():
            if n != "long10":
                self.assertFalse(set(self.prof["sources"]) & set(p.get("sources") or self.corpus["sources"]), n)

    def test_pinned(self):
        srcs = [(n, self.corpus["sources"][n]) for n in self.prof["sources"]] + list(self.r8d["sources"].items())
        for name, src in srcs:
            with self.subTest(source=name):
                self.assertRegex(src.get("sha256") or "", r"^[0-9a-f]{64}$")
                self.assertTrue(src.get("license") and src.get("terms"))
                if src["kind"] == "github-tree":
                    self.assertRegex(src["commit"], r"^[0-9a-f]{40}$")
                    self.assertRegex(src["tree_sha"], r"^[0-9a-f]{40}$")
                    self.assertTrue(all(isinstance(s, str) for s in src["suffixes"]))

    def test_disjoint(self):
        """long10 and L+ share no repository and no RFC with each other or with any earlier source."""
        l10 = [self.corpus["sources"][n] for n in self.prof["sources"]]
        lp = list(self.r8d["sources"].values())
        others = [s for n, s in self.corpus["sources"].items() if n not in self.prof["sources"]]
        for f in sorted((TRAIN / "data").glob("sources_*.yaml")):
            if f.name != "sources_r8d.yaml":
                others += list((yaml.safe_load(f.read_text("utf-8")).get("sources") or {}).values())
        repos = lambda srcs: {s["repo"] for s in srcs if s.get("kind") == "github-tree"}  # noqa: E731
        rfcs = lambda srcs: {p for s in srcs if s.get("genre") == "rfc" for p in s.get("paths", [])}  # noqa: E731
        self.assertFalse(repos(l10) & repos(lp))
        self.assertFalse((repos(l10) | repos(lp)) & repos(others))
        self.assertTrue(rfcs(l10) and rfcs(lp))
        self.assertFalse(rfcs(l10) & rfcs(lp))
        self.assertFalse((rfcs(l10) | rfcs(lp)) & rfcs(others))


if __name__ == "__main__":
    unittest.main()
