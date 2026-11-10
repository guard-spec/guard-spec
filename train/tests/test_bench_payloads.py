"""Tests of the payload selection of bench/long/build.py (no network, no tokenizer file).

The attack payloads of the long-document benchmark come from the eval/ dev half only (ids ending in
hex 0-7, eval/README.md), so that a model selected on the bench dev slice never saw eval-holdout
wording; the bench dev/holdout split of a payload is a separate hash of its id (split_of).

Needs the bench project's imports (PyYAML, tokenizers); skipped without them.
"""

from __future__ import annotations

import collections
import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "bench" / "long"))

try:
    import yaml
    import build as bench_build
except ImportError:  # pragma: no cover
    yaml = None
    bench_build = None

DEV_HEX = "01234567"
HOLDOUT_HEX = "89abcdef"


@unittest.skipIf(bench_build is None, "bench/long/build.py needs PyYAML and tokenizers")
class BenchPayloadsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = yaml.safe_load((REPO / "bench" / "long" / "corpus.yaml").read_text("utf-8"))
        cls.spec = cls.cfg["payloads"]
        cls.eval_rows = {}
        for f in cls.spec["files"]:
            with open(REPO / f, encoding="utf-8") as fh:
                for line in fh:
                    r = json.loads(line)
                    cls.eval_rows[r["id"]] = r

    def payloads(self, profile: str) -> list[dict]:
        prof = self.cfg["profiles"][profile]
        return bench_build.load_payloads(self.spec, prof["payloads_per_lang"], self.cfg["synthetic"]["seed"])

    def test_spec_names_the_eval_dev_half(self):
        self.assertEqual(self.spec["dev_last_hex"], DEV_HEX)
        self.assertNotIn("holdout_last_hex", self.spec)
        self.assertTrue(set(DEV_HEX).isdisjoint(HOLDOUT_HEX))
        self.assertEqual(set(DEV_HEX) | set(HOLDOUT_HEX), set("0123456789abcdef"))

    def test_every_payload_is_an_eval_dev_attack_row(self):
        for profile in self.cfg["profiles"]:
            with self.subTest(profile=profile):
                ps = self.payloads(profile)
                self.assertTrue(ps)
                for p in ps:
                    self.assertIn(p["id"][-1], DEV_HEX, p["id"])
                    self.assertNotIn(p["id"][-1], HOLDOUT_HEX, p["id"])
                    row = self.eval_rows[p["id"]]
                    self.assertEqual(row["label"], "attack")
                    self.assertEqual(row["text"], p["text"])
                    self.assertTrue(self.spec["min_chars"] <= len(p["text"]) <= self.spec["max_chars"])

    def test_payload_counts_per_language(self):
        for profile, prof in self.cfg["profiles"].items():
            with self.subTest(profile=profile):
                n = collections.Counter(p["lang"] for p in self.payloads(profile))
                self.assertEqual(n, {"en": prof["payloads_per_lang"], "vi": prof["payloads_per_lang"]})

    def test_dev_half_has_enough_rows(self):
        """The dev half must cover the largest profile for each language, without a shortfall."""
        want = max(p["payloads_per_lang"] for p in self.cfg["profiles"].values())
        have = collections.Counter(
            r["lang"] for r in self.eval_rows.values()
            if r["label"] == "attack" and r["id"][-1] in DEV_HEX
            and self.spec["min_chars"] <= len(r["text"]) <= self.spec["max_chars"])
        for lang in ("en", "vi"):
            self.assertGreaterEqual(have[lang], want, lang)

    def test_selection_is_deterministic(self):
        a = [p["id"] for p in self.payloads("full")]
        b = [p["id"] for p in self.payloads("full")]
        self.assertEqual(a, b)
        self.assertEqual(len(a), len(set(a)))

    def test_bench_split_is_a_separate_hash_of_the_payload_id(self):
        """Every payload is eval dev; the bench slice (split_of) hashes the payload id again, so both bench
        slices get payloads and the two slices use disjoint payloads."""
        ps = self.payloads("full")
        by_slice: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
        for p in ps:
            control = {"id": f"control-{p['id']}", "kind": "control", "payload_id": p["id"]}
            attack = {"id": f"attack-{p['id']}-pos_start", "kind": "attack", "payload_id": p["id"]}
            s = bench_build.split_of(control)
            self.assertEqual(s, bench_build.split_of(attack))
            want = "dev" if int(hashlib.sha256(p["id"].encode()).hexdigest()[-1], 16) < 8 else "holdout"
            self.assertEqual(s, want)
            by_slice[(p["lang"], s)].add(p["id"])
        for lang in ("en", "vi"):
            self.assertTrue(by_slice[(lang, "dev")], lang)
            self.assertTrue(by_slice[(lang, "holdout")], lang)
            self.assertTrue(by_slice[(lang, "dev")].isdisjoint(by_slice[(lang, "holdout")]))


if __name__ == "__main__":
    unittest.main()
