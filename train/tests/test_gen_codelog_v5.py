"""Tests of train/data/gen_codelog_v5.py (standard library only, no network).

    python3 -m unittest discover -s train/tests -v
"""

from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "data"))

import gen_codelog_v5 as gen  # noqa: E402

ATTACK = re.compile(r"ignore (all |the )?(previous|prior) (instructions|rules)|prompt[ _-]?inject|jailbreak|system prompt|"
                    r"developer mode|exfiltrat|(bỏ qua|quên) (mọi|tất cả) (hướng dẫn|chỉ thị)", re.I)


def literal_lists(path: Path, names: set[str]) -> dict[str, list[str]]:
    """Top-level list literals of a module, read without importing it (bench/long needs third-party packages)."""
    out = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in names:
                out[node.targets[0].id] = ast.literal_eval(node.value)
    return out


def norm(s: str) -> str:
    return re.sub(r"\{[a-z]+\}", "", s).lower().strip()


def grams(s: str, k: int = 5) -> set[str]:
    s = " ".join(s.split())
    return {s[i:i + k] for i in range(max(1, len(s) - k + 1))}


class GenCodelogV5(unittest.TestCase):
    def test_byte_identical(self):
        self.assertEqual(gen.sample_md5(8), gen.sample_md5(8))

    def test_seed_differs_from_eval_sets(self):
        for path in (REPO / "eval" / "codelog" / "build.py", REPO / "eval" / "build" / "build.py"):
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "SEED":
                    self.assertNotEqual(ast.literal_eval(node.value), gen.SEED, path)
        seed = re.search(r"(?m)^\s+seed: (\d+)", (REPO / "bench" / "long" / "corpus.yaml").read_text(encoding="utf-8"))
        self.assertNotEqual(int(seed.group(1)), gen.SEED)

    def test_catalogs_differ_from_evaluation_templates(self):
        ev = literal_lists(REPO / "eval" / "codelog" / "build.py", {"EN_MSG", "VI_MSG", "SVCS"})
        bl = literal_lists(REPO / "bench" / "long" / "build.py", {"EN_LOG", "VI_LOG", "EN_SENT", "VI_SENT"})
        theirs = [norm(m) for v in list(ev.values()) + list(bl.values()) for m in v]
        self.assertGreater(len(theirs), 80)
        ours = [norm(m) for cat in (gen.LOG_EN, gen.LOG_VI, gen.TRACE_VI_MSG) for s in cat.values() for m in s]
        for m in ours:
            self.assertNotIn(m, theirs)
            best = max(len(grams(m) & grams(t)) / len(grams(m) | grams(t)) for t in theirs)
            self.assertLess(best, 0.6, m)
        for s in gen.SETS:
            self.assertFalse(set(gen.SERVICES[s]) & set(ev["SVCS"]))

    def test_template_sets_are_disjoint(self):
        for cat in (gen.LOG_EN, gen.LOG_VI, gen.TRACE_VI_MSG, gen.SERVICES, gen.LOG_FORMATS):
            a, b, c = (set(cat[s]) for s in gen.SETS)
            self.assertFalse(a & b or a & c or b & c, cat)

    def test_units_are_benign_and_nonempty(self):
        for kind in gen.GENERATORS:
            for s in gen.SETS:
                for i in range(20):
                    u = gen.unit(kind, s, i)
                    self.assertTrue(u.strip())
                    self.assertIsNone(ATTACK.search(u), (kind, s, i))

    def test_vi_repeat_has_a_repeated_line(self):
        for i in range(30):
            ls = gen.unit("log_vi_repeat", "A", i).split("\n")
            runs = [k for k in range(len(ls) - 1) if ls[k] == ls[k + 1]]
            self.assertTrue(runs, i)


if __name__ == "__main__":
    unittest.main()
