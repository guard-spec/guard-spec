"""Shingle guard between bench/long and the training data (RF-895d3533, R0).

    cd train && uv run --frozen python data/bench_guard.py --bench <docs.jsonl> --tokenizer <tokenizer.json> rows.jsonl...
    python3 data/bench_guard.py --bench <docs.jsonl> --words rows.jsonl...      # word-level approximation

Rule: no run of 50 consecutive content tokens (the classifier's tokenizer, no special tokens) of a
training row may occur in any bench/long document. The index holds a 64-bit hash of every 50-token
shingle of every document of the corpus (about 9.5 million for the full profile) in a sorted array; a
row is checked by binary search of its own shingles. A row with fewer than 50 tokens cannot leak by this
rule; the v5 guard (fingerprints, character 5-gram Jaccard, line copies) still applies to it.

`--words` is the documented approximation for a machine without the tokenizer: tokens are the
whitespace-separated words of the NFC text, lowercased, and the shingle is 50 words. A word is about
1.3 tokens on average, so a 50-word shingle is longer than a 50-token one and finds fewer overlaps;
the builder (data/build_v6.py) always uses the tokenizer. The same code path serves both, through the
`tokenize` callable of ShingleIndex.

Hashes: polynomial over the token ids modulo 2^64 (Horner form, P = 1_000_003), then a splitmix-style
mix. NumPy vectorizes the corpus side; the pure-Python rolling form (no dependency) gives the same
values, which test_bench_guard checks.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import unicodedata
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    import numpy as np
except ImportError:  # the tests run with the standard library only
    np = None

K = 50
P = 1_000_003
MASK = (1 << 64) - 1
PK = pow(P, K - 1, 1 << 64)  # P^(K-1) mod 2^64, for the rolling update


def mix(h: int) -> int:
    h ^= h >> 29
    h = (h * 0xBF58476D1CE4E5B9) & MASK
    h ^= h >> 32
    return h


def shingle_hashes_py(ids: Sequence[int], k: int = K) -> list[int]:
    """Hashes of the k-shingles of ids (pure Python, rolling): [] when len(ids) < k."""
    n = len(ids)
    if n < k:
        return []
    h = 0
    for j in range(k):
        h = (h * P + ids[j]) & MASK
    out = [mix(h)]
    pk = pow(P, k - 1, 1 << 64)
    for i in range(k, n):
        h = ((h - ids[i - k] * pk) * P + ids[i]) & MASK
        out.append(mix(h))
    return out


def shingle_hashes_np(ids: Sequence[int], k: int = K):
    """The same hashes as shingle_hashes_py, vectorized (uint64 array)."""
    a = np.asarray(ids, dtype=np.uint64)
    n = len(a)
    if n < k:
        return np.zeros(0, dtype=np.uint64)
    with np.errstate(over="ignore"):
        h = np.zeros(n - k + 1, dtype=np.uint64)
        p = np.uint64(P)
        for j in range(k):
            h = h * p + a[j: n - k + 1 + j]
        h ^= h >> np.uint64(29)
        h *= np.uint64(0xBF58476D1CE4E5B9)
        h ^= h >> np.uint64(32)
    return h


def shingle_hashes(ids: Sequence[int], k: int = K):
    return shingle_hashes_np(ids, k) if np is not None else shingle_hashes_py(ids, k)


def word_tokens(text: str) -> list[int]:
    """The word-level approximation: one id per distinct lowercased NFC word (stable within a process)."""
    return [_WORD_IDS.setdefault(w, len(_WORD_IDS)) for w in unicodedata.normalize("NFC", text).lower().split()]


_WORD_IDS: dict[str, int] = {}


class ShingleIndex:
    """Every k-shingle of the reference documents, with the label (document id) of its first occurrence."""

    def __init__(self, tokenize: Callable[[str], Sequence[int]], k: int = K):
        self.tokenize, self.k = tokenize, k
        self.labels: list[str] = []
        self._parts: list = []  # per document: (hashes, label index)
        self.docs = 0
        self.tokens = 0
        self.shingles = 0
        self._hashes = None
        self._owner = None
        self._map: dict[int, int] | None = None

    def add(self, text: str, label: str) -> int:
        ids = self.tokenize(text)
        h = shingle_hashes(ids, self.k)
        self.docs += 1
        self.tokens += len(ids)
        self.shingles += len(h)
        if len(h):
            self.labels.append(label)
            self._parts.append((h, len(self.labels) - 1))
        self._hashes = None
        return len(h)

    def _build(self):
        if np is not None:
            if not self._parts:
                self._hashes = np.zeros(0, dtype=np.uint64)
                self._owner = np.zeros(0, dtype=np.int64)
                return
            allh = np.concatenate([h for h, _ in self._parts])
            owner = np.concatenate([np.full(len(h), j, dtype=np.int64) for h, j in self._parts])
            self._hashes, first = np.unique(allh, return_index=True)
            self._owner = owner[first]
        else:
            m: dict[int, int] = {}
            for h, j in self._parts:
                for x in h:
                    m.setdefault(x, j)
            self._map = m
        self._parts = []  # the arrays are in the index now
        self.unique = len(self._hashes) if self._map is None else len(self._map)

    def check(self, text: str) -> tuple[int, list[str]]:
        """(shingles of text, labels of the reference documents sharing one), in order of first hit."""
        if self._hashes is None and self._map is None:
            self._build()
        ids = self.tokenize(text)
        h = shingle_hashes(ids, self.k)
        if len(h) == 0:
            return 0, []
        hits: list[str] = []
        if self._map is not None:
            for x in h:
                j = self._map.get(x)
                if j is not None and self.labels[j] not in hits:
                    hits.append(self.labels[j])
            return len(h), hits
        if len(self._hashes) == 0:
            return len(h), []
        pos = np.searchsorted(self._hashes, h)
        pos[pos >= len(self._hashes)] = 0
        found = self._hashes[pos] == h
        for j in self._owner[pos[found]].tolist():
            if self.labels[j] not in hits:
                hits.append(self.labels[j])
        return len(h), hits

    def filter_rows(self, rows: Iterable[dict], counts: collections.Counter, tag: str,
                    examples: dict | None = None, text_key: str = "text") -> list[dict]:
        """The rows without a shingle of the index; drops are counted per tag (and per row `kind` when present)."""
        kept = []
        for r in rows:
            n, hits = self.check(r[text_key])
            counts[f"bench_shingle:checked:{tag}"] += 1
            if n == 0:
                counts[f"bench_shingle:short:{tag}"] += 1
            if hits:
                counts[f"bench_shingle:dropped:{tag}"] += 1
                if r.get("kind"):
                    counts[f"bench_shingle:dropped:{tag}:{r['kind']}"] += 1
                if examples is not None:
                    examples.setdefault(tag, []).append(f"{r.get('origin') or r.get('id') or '?'} ~ {', '.join(hits[:3])}")
                continue
            kept.append(r)
        return kept


def load_bench(index: ShingleIndex, docs_jsonl: Path) -> None:
    with open(docs_jsonl, encoding="utf-8") as f:
        for ln in f:
            d = json.loads(ln)
            index.add(d["text"], d["id"])


def tokenizer_fn(path: Path) -> Callable[[str], list[int]]:
    from tokenizers import Tokenizer

    t = Tokenizer.from_file(str(path))
    t.no_truncation()
    t.no_padding()
    return lambda s: t.encode(s, add_special_tokens=False).ids


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bench", required=True, help="bench/long docs.jsonl (any profile)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tokenizer", help="tokenizer.json of the classifier (content tokens)")
    g.add_argument("--words", action="store_true", help="word-level approximation (see the module docstring)")
    ap.add_argument("--k", type=int, default=K)
    ap.add_argument("--out", help="write the report as JSON here (stdout otherwise)")
    ap.add_argument("rows", nargs="+", help="JSONL files of training rows (field `text`)")
    a = ap.parse_args(argv)
    tok = word_tokens if a.words else tokenizer_fn(Path(a.tokenizer))
    ix = ShingleIndex(tok, a.k)
    load_bench(ix, Path(a.bench))
    counts: collections.Counter = collections.Counter()
    examples: dict = {}
    for p in a.rows:
        with open(p, encoding="utf-8") as f:
            rows = [json.loads(ln) for ln in f if ln.strip()]
        ix.filter_rows(rows, counts, Path(p).name, examples)
    rep = {"bench": str(a.bench), "k": a.k, "tokens": "words" if a.words else "tokenizer",
           "bench_docs": ix.docs, "bench_tokens": ix.tokens, "bench_shingles": ix.shingles, "bench_unique_shingles": ix.unique,
           "counts": dict(sorted(counts.items())), "examples": {k: v[:20] for k, v in examples.items()}}
    body = json.dumps(rep, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        Path(a.out).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    dropped = sum(v for k, v in counts.items() if k.startswith("bench_shingle:dropped:") and k.count(":") == 2)
    return 1 if dropped else 0


if __name__ == "__main__":
    sys.exit(main())
