"""Tests of train/windows.py: gateway windows, Go parity and window labels.

    cd train && uv run --frozen pytest tests/test_windows.py
    cd train && uv run --frozen python -m unittest discover -s tests -v    # with the tokenizer check

The window and label tests use the standard library only. The tokenizer check needs the `tokenizers`
package and the base model's tokenizer.json (Hugging Face cache, $GUARDSPEC_TOKENIZER, or a pulled
model under models/); it skips without them.
"""

from __future__ import annotations

import glob
import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))

import windows as W  # noqa: E402

FIXTURE = REPO / "internal" / "onnx" / "testdata" / "window_parity.json"


def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def tokenizer_path():
    cands = [os.environ.get("GUARDSPEC_TOKENIZER", "")]
    cands += glob.glob(os.path.expanduser(
        "~/.cache/huggingface/hub/models--intfloat--multilingual-e5-small/snapshots/614241f622f53c4eeff9890bdc4f31cfecc418b3/tokenizer.json"))
    cands += [str(REPO / "models" / d / "tokenizer.json") for d in
              ("cache/multilingual-e5-small", "local/guardspec-classifier-v3b", "local/guardspec-classifier-v4")]
    return next((c for c in cands if c and Path(c).is_file()), None)


class TokenRanges(unittest.TestCase):
    def test_geometry(self):
        self.assertEqual(W.token_ranges(0), [(0, 0)])
        self.assertEqual(W.token_ranges(254), [(0, 254)])
        self.assertEqual(W.token_ranges(255), [(0, 254), (190, 255)])
        self.assertEqual(W.token_ranges(444), [(0, 254), (190, 444)])
        self.assertEqual(W.token_ranges(445), [(0, 254), (190, 444), (380, 445)])
        for n in range(0, 2000, 7):
            rs = W.token_ranges(n)
            self.assertEqual(rs[0][0], 0)
            self.assertEqual(rs[-1][1], n)
            for (s0, e0), (s1, e1) in zip(rs, rs[1:]):
                self.assertEqual(s1 - s0, 190)
                self.assertEqual(e0 - s1, 64)  # overlap, every window but the last is full
            self.assertTrue(all(e - s <= 254 for s, e in rs))

    def test_small_geometry_as_go_unit_test(self):
        # windows_test.go: MaxLength 10, Stride 2 -> 8 content tokens, step 6; 44 tokens -> 7 windows.
        rs = W.token_ranges(44, max_len=10, stride=2)
        self.assertEqual(rs, [(i * 6, min(i * 6 + 8, 44)) for i in range(7)])


class GoParity(unittest.TestCase):
    """The windows Go cuts (fixture written by internal/onnx/window_parity_integration_test.go)."""

    def test_windows_match_go(self):
        f = fixture()
        self.assertEqual((f["max_len"], f["stride"]), (W.MAX_LEN, W.STRIDE))
        for x in f["texts"]:
            b = x["text"].encode("utf-8")
            offs = [tuple(o) for o in x["offsets"]]
            ranges = W.token_ranges(len(x["ids"]), f["max_len"], f["stride"], len(f["prefix"]) + len(f["suffix"]))
            spans = W.window_byte_spans(b, offs, ranges)
            got = [dict(start=s, end=e, byte_start=bs, byte_end=be) for (s, e), (bs, be) in zip(ranges, spans)]
            self.assertEqual(got, x["windows"], x["name"])
        self.assertGreaterEqual(sum(len(x["windows"]) > 1 for x in f["texts"]), 5)

    def test_tokenizer_matches_go(self):
        path = tokenizer_path()
        try:
            import tokenizers  # noqa: F401
        except ImportError:
            self.skipTest("tokenizers not installed (run with uv run --frozen python -m unittest)")
        if not path:
            self.skipTest("no tokenizer.json (set GUARDSPEC_TOKENIZER)")
        tok = W.GatewayTokenizer(path)
        f = fixture()
        self.assertEqual((tok.prefix, tok.suffix), (f["prefix"], f["suffix"]))
        for x in f["texts"]:
            ids, offs = tok.encode_offsets(x["text"])
            self.assertEqual(ids, x["ids"], x["name"])
            self.assertEqual([list(o) for o in offs], x["offsets"], x["name"])
        # batch encoding gives the same
        batch = tok.encode_batch_offsets([x["text"] for x in f["texts"]])
        self.assertEqual([b[0] for b in batch], [x["ids"] for x in f["texts"]])


def fake_offsets(n, width=4):
    """n tokens of `width` bytes each (ASCII text of n*width bytes)."""
    return [(i * width, (i + 1) * width) for i in range(n)]


def emb_row(n_tokens, p_start, p_len, labels=("jailbreak",), width=4):
    text = "a" * (n_tokens * width)
    return dict(text=text, labels=sorted(set(labels) | {"indirect_injection"}), payload_labels=list(labels),
                byte_spans=[[p_start * width, (p_start + p_len) * width]], kind="embedded")


class Labels(unittest.TestCase):
    def labels(self, row, n):
        return [(w.start, w.end, w.labels, w.why) for w in W.label_windows(row, fake_offsets(n))]

    def test_payload_inside_one_window(self):
        # 600 tokens -> windows [0,254) [190,444) [380,600); payload 20..60 only in window 0
        got = self.labels(emb_row(600, 20, 40), 600)
        self.assertEqual([g[3] for g in got], ["payload", "host", "host"])
        self.assertEqual(got[0][2], ["indirect_injection", "jailbreak"])
        self.assertEqual(got[1][2], ["benign"])

    def test_payload_in_overlap_is_attack_in_both(self):
        got = self.labels(emb_row(600, 200, 40), 600)  # 200..240: in windows 0 and 1
        self.assertEqual([g[3] for g in got], ["payload", "payload", "host"])

    def test_share_thresholds(self):
        # payload 100 tokens at 204..304: window 0 [0,254) holds 50 (0.5 -> drop), window 1 holds all.
        ws = W.label_windows(emb_row(600, 204, 100), fake_offsets(600))
        self.assertEqual([(w.why, w.payload_tokens) for w in ws], [("partial", 50), ("payload", 100), ("host", 0)])
        self.assertIsNone(ws[0].labels)
        # 60% exactly is an attack: 100 tokens at 194..294 -> window 0 holds 60
        ws = W.label_windows(emb_row(600, 194, 100), fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].payload_tokens, ws[0].share), ("payload", 60, 0.6))
        # 30% exactly is dropped: 100 tokens at 224..324 -> window 0 holds 30
        ws = W.label_windows(emb_row(600, 224, 100), fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].payload_tokens), ("partial", 30))

    def test_fragment_rule(self):
        # 100-token payload, window 0 holds 4 (benign fragment) or 5..29 (dropped)
        ws = W.label_windows(emb_row(600, 250, 100), fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].labels, ws[0].payload_tokens), ("fragment", ["benign"], 4))
        ws = W.label_windows(emb_row(600, 249, 100), fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].labels, ws[0].payload_tokens), ("partial", None, 5))
        ws = W.label_windows(emb_row(600, 230, 100), fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].payload_tokens), ("partial", 24))

    def test_split_adjacent_spans_count_together(self):
        row = emb_row(600, 0, 0)
        row["byte_spans"] = [[100 * 4, 130 * 4], [140 * 4, 170 * 4]]  # two halves, 60 tokens
        ws = W.label_windows(row, fake_offsets(600))
        self.assertEqual((ws[0].why, ws[0].payload_tokens), ("payload", 60))

    def test_label_order(self):
        order = ["benign", "direct_injection", "indirect_injection", "jailbreak", "prompt_extraction"]
        row = emb_row(300, 10, 10, labels=("prompt_extraction", "direct_injection"))
        self.assertEqual(W.label_windows(row, fake_offsets(300), label_order=order)[0].labels,
                         ["direct_injection", "indirect_injection", "prompt_extraction"])

    def test_rows_without_spans(self):
        benign = dict(text="a" * 2400, labels=["benign"])
        self.assertEqual([(w.labels, w.why) for w in W.label_windows(benign, fake_offsets(600))],
                         [(["benign"], "row")] * 3)
        attack = dict(text="a" * 2400, labels=["jailbreak"])
        self.assertEqual([(w.labels, w.why) for w in W.label_windows(attack, fake_offsets(600))],
                         [(["jailbreak"], "row"), (None, "tail"), (None, "tail")])
        twin = dict(text="a" * 2400, labels=["benign"], kind="twin")
        self.assertTrue(all(w.labels == ["benign"] for w in W.label_windows(twin, fake_offsets(600))))

    def test_short_row_one_window(self):
        ws = W.label_windows(emb_row(100, 10, 20), fake_offsets(100))
        self.assertEqual([(w.start, w.end, w.why) for w in ws], [(0, 100, "payload")])
        self.assertEqual((ws[0].byte_start, ws[0].byte_end), (0, 400))

    def test_byte_offsets_and_spans(self):
        text = "Tiếng Việt 😀 x"
        chars = [(0, 5), (5, 10), (11, 12), (13, 14)]
        self.assertEqual(W.char_to_byte_offsets(text, chars), [(0, 7), (7, 14), (15, 19), (20, 21)])
        # A window edge inside a rune widens to the rune (spanIn in long.go).
        b = text.encode()
        self.assertEqual(W._span_in(b, 3, 16), (2, 19))  # 3 is inside "ế", 16 inside the emoji
        self.assertEqual(W._span_in(b, -3, 99), (0, len(b)))

    def test_worst_case(self):
        self.assertEqual(W.worst_case([[0.9, 0.1, 0.2], [0.4, 0.05, 0.7], [0.8, 0.3, 0.1]]), [0.4, 0.3, 0.7])


if __name__ == "__main__":
    unittest.main()
