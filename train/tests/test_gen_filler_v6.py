"""Tests of train/data/gen_filler_v6.py (standard library only, no network).

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

import gen_codelog_v5 as gen5  # noqa: E402
import gen_filler_v6 as gen  # noqa: E402

# An instruction to a model, as opposed to a sentence about one: line-initial imperatives only.
INSTR = re.compile(r"^\W*(ignore|disregard|forget|bỏ qua|phớt lờ) (all |the |any |mọi |tất cả )?(previous|prior|above|hướng dẫn|chỉ dẫn)|"
                   r"^\W*you are now\b|^\W*(từ giờ|bây giờ) bạn (là|sẽ)", re.I | re.M)


def literal_lists(path: Path, names: set[str]) -> dict[str, list[str]]:
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


class GenFillerV6(unittest.TestCase):
    def test_byte_identical(self):
        self.assertEqual(gen.sample_md5(8), gen.sample_md5(8))

    def test_seed_differs_from_other_generators_and_evaluation_sets(self):
        self.assertNotEqual(gen.SEED, gen5.SEED)
        for path in (REPO / "eval" / "codelog" / "build.py", REPO / "eval" / "build" / "build.py"):
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "SEED":
                    self.assertNotEqual(ast.literal_eval(node.value), gen.SEED, path)
        seed = re.search(r"(?m)^\s+seed: (\d+)", (REPO / "bench" / "long" / "corpus.yaml").read_text(encoding="utf-8"))
        self.assertNotEqual(int(seed.group(1)), gen.SEED)

    def test_catalogs_differ_from_evaluation_templates(self):
        ev = literal_lists(REPO / "eval" / "codelog" / "build.py", {"EN_MSG", "VI_MSG"})
        bl = literal_lists(REPO / "bench" / "long" / "build.py", {"EN_LOG", "VI_LOG", "EN_SENT", "VI_SENT", "EN_HARDNEG", "VI_HARDNEG"})
        self.assertEqual(len(bl), 6)
        theirs = [norm(m) for v in list(ev.values()) + list(bl.values()) for m in v]
        self.assertGreater(len(theirs), 100)
        ours = [norm(m) for cat in (gen.HUMAN_EN, gen.HUMAN_VI, gen.SEC_EN, gen.SEC_VI) for s in cat.values() for m in s]
        self.assertGreater(len(ours), 150)
        for m in ours:
            self.assertNotIn(m, theirs)
            best = max(len(grams(m) & grams(t)) / len(grams(m) | grams(t)) for t in theirs)
            self.assertLess(best, 0.6, m)

    def test_template_sets_are_disjoint(self):
        for cat in (gen.HUMAN_EN, gen.HUMAN_VI, gen.SEC_EN, gen.SEC_VI, gen.ORGS, gen.ORGS_VI, gen.TOOLS, gen.TOOLS_VI):
            a, b, c = (set(cat[s]) for s in gen.SETS)
            self.assertFalse(a & b or a & c or b & c, cat)
        for cat in (gen.HUMAN_EN, gen.HUMAN_VI, gen.SEC_EN, gen.SEC_VI):
            for s in gen.SETS:
                self.assertEqual(len(cat[s]), len(set(cat[s])), s)

    def test_units_are_benign_and_nonempty(self):
        for kind in gen.GENERATORS:
            for s in gen.SETS:
                for i in range(25):
                    u = gen.unit(kind, s, i)
                    self.assertTrue(u.strip())
                    self.assertIsNone(INSTR.search(u), (kind, s, i))
                    if kind.startswith("human_log"):
                        self.assertGreaterEqual(u.count("\n"), 8)
                    else:
                        self.assertNotIn("{", u)  # every slot filled
                        self.assertGreaterEqual(len(u.split(". ")), 3)

    def test_security_prose_discusses_injection(self):
        for lang in ("en", "vi"):
            text = " ".join(gen.unit(f"secprose_{lang}", "A", i) for i in range(10)).lower()
            self.assertIn("prompt injection" if lang == "en" else "chèn lệnh", text)

    def test_human_lines(self):
        for lang in ("en", "vi"):
            for s in gen.SETS:
                lines = gen.human_lines(lang, s, 3, 4)
                self.assertEqual(len(lines), 4)
                self.assertTrue(all(6 <= len(ln.split()) <= 40 for ln in lines), lines)
                self.assertEqual(lines, gen.human_lines(lang, s, 3, 4))


if __name__ == "__main__":
    unittest.main()
