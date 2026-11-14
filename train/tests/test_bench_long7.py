"""Tests of the `long7` profile of bench/long/corpus.yaml, the v8 holdout (RF-3a9ce3f9 R7; no network): its
sources are pinned and licensed, used by no other profile and by no v7 training source (other files, row
groups, subtrees, RFCs and U.S. Code titles), and its attack payloads are the eval/ dev-half rows after the
ones long6 used (embed_long.py --eval-payloads 24 --eval-skip 96).

    cd train && uv run --frozen python -m unittest tests/test_bench_long7.py -v

Needs PyYAML; skipped without it.
"""

from __future__ import annotations

import collections
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(REPO / "bench" / "long"))

try:
    import yaml
except ImportError as e:  # plain python3 without PyYAML
    raise unittest.SkipTest(f"needs PyYAML (uv run): {e}")

CORPUS = yaml.safe_load((REPO / "bench" / "long" / "corpus.yaml").read_text("utf-8"))
V7 = yaml.safe_load((TRAIN / "data" / "sources_v7.yaml").read_text("utf-8"))


class Long7ProfileTest(unittest.TestCase):
    prof = CORPUS["profiles"]["long7"]

    def test_profile(self):
        self.assertEqual(self.prof["id_prefix"], "long7-")
        self.assertEqual(self.prof["payloads_per_lang"], 0)
        self.assertNotIn(self.prof["synthetic_seed"], [p.get("synthetic_seed") for n, p in CORPUS["profiles"].items()
                                                      if n != "long7"] + [CORPUS["synthetic"]["seed"]])
        self.assertRegex(CORPUS["outputs"]["long7"], r"^[0-9a-f]{64}$")

    def test_sources_are_pinned_and_licensed(self):
        for name in self.prof["sources"]:
            src = CORPUS["sources"][name]
            with self.subTest(source=name):
                self.assertRegex(src.get("sha256") or "", r"^[0-9a-f]{64}$")
                self.assertTrue(src.get("license") and src.get("terms"))
                if src["kind"] == "hf-parquet":
                    self.assertRegex(src["revision"], r"^[0-9a-f]{40}$")
                    self.assertRegex(src["file_sha256"], r"^[0-9a-f]{64}$")
                if src["kind"] == "github-tree":
                    self.assertRegex(src["commit"], r"^[0-9a-f]{40}$")
                    self.assertRegex(src["tree_sha"], r"^[0-9a-f]{40}$")
                    self.assertRegex(src["license"], r"^(Apache-2\.0|CC-BY-4\.0|MIT|BSD)")

    def test_sources_are_used_by_no_other_profile_and_no_training_source(self):
        mine = set(self.prof["sources"])
        for n, p in CORPUS["profiles"].items():
            if n != "long7":
                self.assertFalse(mine & set(p.get("sources") or CORPUS["sources"]), n)
        others = {n: s for n, s in CORPUS["sources"].items() if n not in mine} | V7["sources"]
        for name in mine:
            src = CORPUS["sources"][name]
            self.assertNotIn("units_of", src, name)
            for on, o in others.items():
                with self.subTest(source=name, other=on):
                    if src["kind"] == "hf-parquet" and o.get("file") == src["file"]:
                        def groups(s):
                            if s.get("row_group_range"):
                                return set(range(*s["row_group_range"]))
                            return set(s.get("row_groups") or [s["row_group"]])
                        self.assertFalse(groups(src) & groups(o))
                    if src["kind"] == "github-tree" and o.get("repo") == src["repo"]:
                        a, b = src["prefix"].rstrip("/") + "/", (o.get("prefix") or "").rstrip("/") + "/"
                        self.assertFalse(a.startswith(b) or b.startswith(a), (a, b))
                    if src["kind"] == "http-text" and o.get("paths"):
                        self.assertFalse(set(src["paths"]) & set(o["paths"]))
                    if src["kind"] == "http-html" and o.get("urls"):
                        self.assertFalse(set(src["urls"]) & set(o["urls"]))

    def test_long7_payloads_follow_long6s(self):
        try:
            import build as bench_build
        except ImportError:
            self.skipTest("bench/long/build.py needs tokenizers")
        spec, seed = CORPUS["payloads"], CORPUS["synthetic"]["seed"]
        rows = bench_build.load_payloads(spec, 120, seed)
        by: dict[str, list[dict]] = collections.defaultdict(list)
        for r in rows:
            by[r["lang"]].append(r)
        for lang in ("en", "vi"):
            self.assertEqual(len(by[lang]), 120, lang)
            long6 = {r["id"] for r in by[lang][72:96]}
            long7 = {r["id"] for r in by[lang][96:120]}
            earlier = {r["id"] for r in by[lang][:96]}
            self.assertEqual(len(long7), 24)
            self.assertFalse(long7 & long6)
            self.assertFalse(long7 & earlier)
            self.assertFalse({normalize(r["text"]) for r in by[lang][96:120]} & {normalize(r["text"]) for r in by[lang][:96]})
            for r in by[lang][96:120]:
                self.assertIn(r["id"][-1], spec["dev_last_hex"])


def normalize(s: str) -> str:
    return " ".join(s.lower().split())


if __name__ == "__main__":
    unittest.main()
