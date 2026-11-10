"""Tests of train/data/sources_v5.yaml (no network): pins, set separation and `windows` quotas.

    cd train && uv run --frozen python -m unittest tests/test_sources_v5.py -v

Needs the train project's packages (PyYAML and build_v5's imports); skipped without them.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "data"))

try:
    import yaml

    import build_v5
except ImportError as e:  # plain python3 without the train project's environment
    raise unittest.SkipTest(f"needs the train project environment (uv run): {e}")

CFG = yaml.safe_load((HERE.parent / "data" / "sources_v5.yaml").read_text("utf-8"))
SOURCES = CFG["sources"]


def repo_of(src: dict) -> str | None:
    m = re.search(r"github\.com/([^/]+/[^/.]+)", src.get("url", "")) or \
        re.search(r"codeload\.github\.com/([^/]+/[^/]+)/", src.get("url", ""))
    return m.group(1).lower() if m else None


class SourcesV5Test(unittest.TestCase):
    def test_every_source_is_pinned(self):
        for name, src in SOURCES.items():
            self.assertTrue(src.get("content_sha256"), name)
            self.assertIn(src["set"], ("A", "B", "C"), name)
            self.assertTrue(src.get("license") and src.get("attribution"), name)
            if src["kind"] == "archive":
                self.assertTrue(src.get("archive_sha256"), name)
                self.assertTrue(src.get("license_file") and src.get("license_match"), name)
                if "codeload.github.com" in src["url"]:
                    self.assertTrue(src["url"].endswith("/" + src["commit"]), name)

    def test_a_repository_is_in_one_set_only(self):
        sets: dict[str, set[str]] = {}
        for name, src in SOURCES.items():
            r = repo_of(src)
            if r:
                sets.setdefault(r, set()).add(src["set"])
        self.assertEqual({r: s for r, s in sets.items() if len(s) > 1}, {})

    def test_excluded_sources_are_not_used(self):
        repos = {repo_of(s) for s in SOURCES.values()}
        for banned in ("golang/go", "guard-spec/guard-spec"):
            self.assertNotIn(banned, repos)

    def test_permissive_licences_only(self):
        for name, src in SOURCES.items():
            self.assertNotRegex(src["license"], r"(?i)GPL|BUSL|SSPL|CC-BY-SA|Elastic", name)

    def test_windows_quotas(self):
        for name, src in SOURCES.items():
            quota = src.get("windows") or {}
            for kind, n in quota.items():
                self.assertIn(kind, src.get("select", {}), name)
                self.assertIn(kind, build_v5.TARGETS[src["set"]], name)
                self.assertGreater(n, 0, name)
        for tset in ("A", "B", "C"):
            for kind, target in build_v5.TARGETS[tset].items():
                total = sum((s.get("windows") or {}).get(kind, 0) for s in SOURCES.values() if s["set"] == tset)
                self.assertLessEqual(total, target, f"{tset}/{kind}: quotas above the kind's target")


if __name__ == "__main__":
    unittest.main()
