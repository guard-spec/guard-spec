# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests of the R8c data (RF-f9e76bb6; no network, no data files): the templates of persona3, split1 and S, the
`long9` profile of bench/long/corpus.yaml and the sources of data/sources_r8c.yaml, and build.py's roff
stripper.

    cd train && uv run --frozen python -m unittest tests/test_r8c.py -v

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
sys.path.insert(0, str(REPO / "bench" / "long"))

import r8c_templates as T  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

SEED = 20261119
LABELS = {"benign", "direct_injection", "indirect_injection", "jailbreak", "prompt_extraction", "data_exfiltration",
          "tool_poisoning", "obfuscation"}


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower()).strip()


def frozen_sets() -> list[str]:
    """Texts R8c must not reuse: multiturn.json and the payload_split dev set."""
    d = json.loads((REPO / "cmd/gateway/testdata/multiturn.json").read_text("utf-8"))
    out = [t for c in d["conversations"] for t in c["turns"]]
    src = (REPO / "internal/inference/rules/payload_split_test.go").read_text("utf-8")
    out += re.findall(r"`([^`]*)`", src)
    return out


class Split1Test(unittest.TestCase):
    def test_shape_and_counts(self):
        cs = T.split1_conversations(SEED)
        self.assertEqual(len(cs), 120)
        self.assertEqual(len({c["id"] for c in cs}), 120)
        for lang in ("en", "vi"):
            for kind in ("attack", "benign"):
                self.assertEqual(sum(1 for c in cs if c["lang"] == lang and c["kind"] == kind), 30)
        for c in cs:
            self.assertTrue(2 <= len(c["turns"]) <= 4, c["id"])
            self.assertTrue(all(t.strip() for t in c["turns"]))
        self.assertEqual(len({tuple(c["turns"]) for c in cs}), 120)

    def test_seeded(self):
        self.assertEqual(T.split1_conversations(SEED), T.split1_conversations(SEED))

    def test_no_frozen_text(self):
        frozen = {norm(t) for t in frozen_sets()}
        for c in T.split1_conversations(SEED):
            for t in c["turns"] + [" ".join(c["turns"])]:
                self.assertNotIn(norm(t), frozen)


class STest(unittest.TestCase):
    def test_counts_labels_seeded(self):
        rows = T.s_rows(SEED, 400, 400, 0.5)
        self.assertEqual(len(rows), 800)
        self.assertEqual(rows, T.s_rows(SEED, 400, 400, 0.5))
        self.assertEqual(len({r["text"] for r in rows}), 800)
        for r in rows:
            self.assertTrue(set(r["labels"]) <= LABELS)
            if r["kind"] == "r8c_split_attack":
                self.assertIn("obfuscation", r["labels"])
            else:
                self.assertEqual(r["labels"], ["benign"])
        for lang in ("en", "vi"):
            self.assertEqual(sum(1 for r in rows if r["lang"] == lang), 400)

    def test_reject(self):
        rows = T.s_rows(SEED, 10, 10, 0.5, reject=lambda t: "str1" in t)
        self.assertFalse(any("str1" in r["text"] for r in rows))

    def test_fragments_disjoint_from_split1(self):
        for lang in ("en", "vi"):
            s = {norm(x) for frs in T.S_FRAGS[lang].values() for f in frs for x in f}
            h = {norm(x) for frs in T.SPLIT1_FRAGS[lang].values() for f in frs for x in f}
            self.assertFalse(s & h, lang)

    def test_no_frozen_text(self):
        frozen = {norm(t) for t in frozen_sets()}
        for r in T.s_rows(SEED, 400, 400, 0.5):
            self.assertNotIn(norm(r["text"]), frozen)


class Persona3Test(unittest.TestCase):
    def test_new_roles(self):
        import persona1_templates as P1

        old = {norm(r[0]) for r in P1.ROLES_EN + P1.ROLES_VI}
        for roles in (T.ROLES_EN_P3, T.ROLES_VI_P3):
            self.assertEqual(len(roles), 12)
            self.assertFalse({norm(r[0]) for r in roles} & old)

    def test_blocks_not_in_earlier_templates(self):
        try:
            import build_r8c_holdouts as H
        except ImportError as e:  # build_short1 needs pyarrow
            self.skipTest(f"needs the train environment (uv run): {e}")
        self.assertEqual(H.check_new_blocks(), [])


class RoffTest(unittest.TestCase):
    def setUp(self):
        if yaml is None:
            self.skipTest("needs PyYAML (uv run)")
        try:
            import build  # noqa: F401
        except ImportError as e:
            self.skipTest(f"needs the bench environment: {e}")

    def test_man(self):
        import build

        src = '.\\" comment\n.TH OPEN 2\n.SH NAME\nopen \\- open a file\n.SH DESCRIPTION\nThe\n.BR open ()\ncall uses \\fIpathname\\fP.\n.PP\nDone.\n'
        t = build.tidy(build.strip_roff(src))
        self.assertEqual(t, "NAME\n\nopen - open a file\n\nDESCRIPTION\n\nThe\nopen()\ncall uses pathname.\n\nDone.")

    def test_mdoc(self):
        import build

        src = ".Dd $Mdocdate$\n.Dt LS 1\n.Sh NAME\n.Nm ls\n.Nd list directory contents\n.Sh SYNOPSIS\n.Nm\n.Op Fl a\n.Ar file\n.Xr stat 2 ,\n"
        t = build.tidy(build.strip_roff(src))
        self.assertEqual(t, "NAME\n\nls\n- list directory contents\n\nSYNOPSIS\n\nls\n-a\nfile\nstat(2) ,")


class SourcesTest(unittest.TestCase):
    def setUp(self):
        if yaml is None:
            self.skipTest("needs PyYAML (uv run)")
        self.corpus = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
        self.r8c = yaml.safe_load((TRAIN / "data/sources_r8c.yaml").read_text("utf-8"))
        self.prof = self.corpus["profiles"]["long9"]

    def test_long9_profile(self):
        self.assertEqual(self.prof["id_prefix"], "long9-")
        self.assertEqual(self.prof["payloads_per_lang"], 0)
        self.assertEqual(self.prof["synthetic"], [])
        self.assertRegex(self.corpus["outputs"]["long9"], r"^[0-9a-f]{64}$")
        for n, p in self.corpus["profiles"].items():
            if n != "long9":
                self.assertFalse(set(self.prof["sources"]) & set(p.get("sources") or self.corpus["sources"]), n)

    def test_pinned(self):
        srcs = [(n, self.corpus["sources"][n]) for n in self.prof["sources"]] + list(self.r8c["sources"].items())
        for name, src in srcs:
            with self.subTest(source=name):
                self.assertRegex(src.get("sha256") or "", r"^[0-9a-f]{64}$")
                self.assertTrue(src.get("license") and src.get("terms"))
                if src["kind"] == "github-tree":
                    self.assertRegex(src["commit"], r"^[0-9a-f]{40}$")
                    self.assertRegex(src["tree_sha"], r"^[0-9a-f]{40}$")
                    self.assertTrue(all(isinstance(s, str) for s in src["suffixes"]))

    def test_disjoint(self):
        """long9 and L share no repository, and no RFC with each other or with any earlier source."""
        l9 = [self.corpus["sources"][n] for n in self.prof["sources"]]
        repos9 = {s["repo"] for s in l9 if s["kind"] == "github-tree"}
        reposL = {s["repo"] for s in self.r8c["sources"].values() if s["kind"] == "github-tree"}
        self.assertFalse(repos9 & reposL)
        others = [s for n, s in self.corpus["sources"].items() if n not in self.prof["sources"]]
        for f in sorted((TRAIN / "data").glob("sources_v*.yaml")):
            others += list((yaml.safe_load(f.read_text("utf-8")).get("sources") or {}).values())
        old_repos = {s.get("repo") for s in others}
        self.assertFalse((repos9 | reposL) & old_repos)

        def rfcs(srcs):
            return {p for s in srcs if s.get("genre") == "rfc" for p in s.get("paths", [])}

        r9, rL, ro = rfcs(l9), rfcs(self.r8c["sources"].values()), rfcs(others)
        self.assertTrue(r9 and rL)
        self.assertFalse(r9 & rL)
        self.assertFalse((r9 | rL) & ro)


if __name__ == "__main__":
    unittest.main()
