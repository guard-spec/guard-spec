"""Tests of train/data/bench_guard.py (standard library; NumPy when present).

    python3 -m unittest discover -s train/tests -v
"""

from __future__ import annotations

import collections
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "data"))

import bench_guard as bg  # noqa: E402


def words(r: random.Random, n: int) -> str:
    return " ".join(f"w{r.randrange(5000)}" for _ in range(n))


class BenchGuardTest(unittest.TestCase):
    def setUp(self):
        r = random.Random(7)
        self.docs = {f"doc-{i}": words(r, 400) for i in range(6)}
        self.ix = bg.ShingleIndex(bg.word_tokens, 50)
        for label, text in self.docs.items():
            self.ix.add(text, label)
        self.r = r

    def test_copy_of_fifty_tokens_is_caught(self):
        src = self.docs["doc-3"].split()
        row = words(self.r, 20) + " " + " ".join(src[100:150]) + " " + words(self.r, 20)
        n, hits = self.ix.check(row)
        self.assertEqual(hits, ["doc-3"])
        self.assertEqual(n, len(row.split()) - 49)

    def test_forty_nine_tokens_pass(self):
        src = self.docs["doc-3"].split()
        row = words(self.r, 30) + " " + " ".join(src[100:149]) + " " + words(self.r, 30)
        self.assertEqual(self.ix.check(row)[1], [])

    def test_short_rows_and_fresh_text_pass(self):
        self.assertEqual(self.ix.check(words(self.r, 49)), (0, []))
        self.assertEqual(self.ix.check(words(self.r, 300))[1], [])
        self.assertEqual(self.ix.check("")[0], 0)

    def test_filter_rows_drops_and_counts(self):
        src = self.docs["doc-1"].split()
        rows = [dict(text=words(self.r, 120), kind="code_go", origin="a"),
                dict(text=" ".join(src[:60]), kind="prose_en", origin="b"),
                dict(text=words(self.r, 10), kind="log_en", origin="c")]
        counts = collections.Counter()
        ex = {}
        kept = self.ix.filter_rows(rows, counts, "set_A", ex)
        self.assertEqual([r["origin"] for r in kept], ["a", "c"])
        self.assertEqual(counts["bench_shingle:dropped:set_A"], 1)
        self.assertEqual(counts["bench_shingle:dropped:set_A:prose_en"], 1)
        self.assertEqual(counts["bench_shingle:checked:set_A"], 3)
        self.assertEqual(counts["bench_shingle:short:set_A"], 1)
        self.assertEqual(ex["set_A"], ["b ~ doc-1"])

    @unittest.skipIf(bg.np is None, "needs NumPy")
    def test_numpy_and_python_hashes_agree(self):
        ids = [self.r.randrange(250_000) for _ in range(300)]
        self.assertEqual(bg.shingle_hashes_np(ids).tolist(), bg.shingle_hashes_py(ids))
        self.assertEqual(bg.shingle_hashes_np(ids[:49]).tolist(), [])
        self.assertEqual(bg.shingle_hashes_py(ids[:49]), [])

    def test_cli_words_mode(self):
        with tempfile.TemporaryDirectory() as d:
            bench = Path(d) / "docs.jsonl"
            bench.write_text("".join(json.dumps({"id": k, "text": v}) + "\n" for k, v in self.docs.items()), "utf-8")
            rows = Path(d) / "rows.jsonl"
            src = self.docs["doc-5"].split()
            rows.write_text(json.dumps({"text": " ".join(src[10:70]), "kind": "prose_vi"}) + "\n" +
                            json.dumps({"text": words(self.r, 80), "kind": "prose_vi"}) + "\n", "utf-8")
            out = Path(d) / "rep.json"
            rc = bg.main(["--bench", str(bench), "--words", "--out", str(out), str(rows)])
            rep = json.loads(out.read_text("utf-8"))
            self.assertEqual(rc, 1)
            self.assertEqual(rep["counts"]["bench_shingle:dropped:rows.jsonl"], 1)
            self.assertEqual(rep["bench_docs"], 6)
            self.assertEqual(rep["bench_shingles"], 6 * (400 - 49))
            clean = Path(d) / "clean.jsonl"
            clean.write_text(json.dumps({"text": words(self.r, 80)}) + "\n", "utf-8")
            self.assertEqual(bg.main(["--bench", str(bench), "--words", "--out", str(out), str(clean)]), 0)


if __name__ == "__main__":
    unittest.main()
