"""Gateway windows and window labels for window-level training (v5, RF-437128e9).

The gateway (internal/onnx) never truncates a long input: it tokenizes the text once without special
tokens, cuts the content tokens into windows of max_len - 2 tokens (256 - [CLS] - [SEP] = 254) that
overlap by `stride` (64) tokens, so a new window starts every 190 tokens, wraps each window in the
special tokens and scores every window; a text's risk is the worst window (lowest p(benign)). This
module reproduces that cut exactly (token ranges and the byte spans of `TokenWindow` from
`(*model).longWindows`) so that the classifier is trained on the windows it is run on, and labels each
window of a row from the payload spans the v5 builder records.

Parity with Go: internal/onnx/testdata/window_parity.json holds texts with the Go tokenizer's ids and
byte offsets and Go's windows; internal/onnx/window_parity_test.go checks Go against it and
train/tests/test_windows.py checks this module against it.

Labels per window (`label_windows`), for a row with payload spans (`byte_spans`, v5 `embedded` rows):

    payload tokens  = content tokens whose byte span overlaps a payload span (all spans of the row
                      together: `split_adjacent` has two halves of one payload)
    share           = payload tokens inside the window / payload tokens of the row
    share >= 0.6    -> the row's labels (payload labels + indirect_injection)
    0.3 <= share < 0.6 -> dropped (neither attack nor benign)
    0 < share < 0.3 -> benign when the window holds at most FRAGMENT_MAX_TOKENS (4) payload tokens
                       (a few words of a payload carry no instruction), otherwise dropped
    share == 0      -> benign (host text)

A benign row (hard negatives, `twin` hosts, the public rows) gives benign windows. An attack row
without spans (the public and owner rows: whole-row labels, mostly one window) keeps its first window
only, which is what training on truncated rows did before v5; its other windows are dropped because
nothing says where the attack is.

Standard library only: the training environment adds the tokenizer (`tokenizers`), the tests do not
need it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_LEN = 256            # model window, special tokens included (thresholds.json max_len)
STRIDE = 64              # overlap between neighbouring windows (internal/onnx defaultStride)
KEEP_SHARE = 0.6         # share of the payload's tokens in a window to label it an attack
DROP_SHARE = 0.3         # below KEEP_SHARE and at or above this: drop the window
FRAGMENT_MAX_TOKENS = 4  # below DROP_SHARE: benign when at most this many payload tokens, else drop
INDIRECT = "indirect_injection"


def token_ranges(n: int, max_len: int = MAX_LEN, stride: int = STRIDE, n_special: int = 2) -> list[tuple[int, int]]:
    """Content-token ranges [start, end) of the windows of a text of n content tokens, as
    (*model).chunk / longWindows cut them: width max_len - n_special, a new window every
    width - stride tokens, the last one ending at n. An empty text gives one empty window."""
    width = max_len - n_special
    step = width - stride
    if width < 1 or step < 1:
        raise ValueError(f"max_len {max_len} / stride {stride} leave no step")
    out, start = [], 0
    while True:
        end = min(start + width, n)
        out.append((start, end))
        if end == n:
            return out
        start += step


def _span_in(b: bytes, start: int, end: int) -> tuple[int, int]:
    """spanIn of long.go: clamp [start, end) to b and widen it to UTF-8 rune boundaries."""
    start = max(0, min(start, len(b)))
    end = max(start, min(end, len(b)))
    while start > 0 and (b[start] & 0xC0) == 0x80:
        start -= 1
    while end < len(b) and (b[end] & 0xC0) == 0x80:
        end += 1
    return start, end


def window_byte_spans(b: bytes, offs: list[tuple[int, int]], ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The byte span [Start, End) of every window, as TokenWindow in long.go: from the first token's start
    to the last token's end, the first window from byte 0, the last to the end of the text."""
    n = len(offs)
    out = []
    for start, end in ranges:
        s = e = 0
        if end > start:
            s, e = offs[start][0], offs[end - 1][1]
        if start == 0:
            s = 0
        if end == n:
            e = len(b)
        out.append(_span_in(b, s, e))
    return out


def char_to_byte_offsets(text: str, offsets: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Python `tokenizers` reports character offsets; the Rust tokenizer the gateway calls reports bytes."""
    pos = [0] * (len(text) + 1)
    acc = 0
    for i, ch in enumerate(text):
        pos[i] = acc
        acc += len(ch.encode("utf-8"))
    pos[len(text)] = acc
    return [(pos[s], pos[e]) for s, e in offsets]


def char_spans_to_bytes(text: str, spans) -> list[tuple[int, int]]:
    return char_to_byte_offsets(text, [tuple(s) for s in spans])


class GatewayTokenizer:
    """The base model's tokenizer.json without truncation or padding, as internal/onnx loads it
    (newHFTokenizer): content ids with byte offsets, and the special tokens found the same way."""

    def __init__(self, path):
        from tokenizers import Tokenizer  # training environment only

        self.t = Tokenizer.from_file(str(path))
        self.t.no_truncation()
        self.t.no_padding()
        probe = "hello world"
        with_sp = self.t.encode(probe, add_special_tokens=True).ids
        without = self.t.encode(probe, add_special_tokens=False).ids
        for i in range(len(with_sp) - len(without) + 1):
            if with_sp[i:i + len(without)] == without:
                self.prefix, self.suffix = with_sp[:i], with_sp[i + len(without):]
                break
        else:
            raise ValueError("cannot locate the special tokens in the post-processor output")

    def encode_offsets(self, text: str) -> tuple[list[int], list[tuple[int, int]]]:
        e = self.t.encode(text, add_special_tokens=False)
        return list(e.ids), char_to_byte_offsets(text, e.offsets)

    def encode_batch_offsets(self, texts: list[str]):
        encs = self.t.encode_batch(list(texts), add_special_tokens=False)
        return [(list(e.ids), char_to_byte_offsets(t, e.offsets)) for t, e in zip(texts, encs)]

    def ids(self, text: str) -> list[int]:
        return list(self.t.encode(text, add_special_tokens=False).ids)


@dataclass
class Window:
    start: int                 # content tokens [start, end)
    end: int
    byte_start: int            # byte span of the text the window covers (TokenWindow.Start/End)
    byte_end: int
    labels: list[str] | None   # None: dropped (not trained on; still scored at text level)
    why: str                   # host / payload / partial / fragment / row / tail
    payload_tokens: int = 0    # payload tokens inside the window
    share: float = 0.0         # payload_tokens / payload tokens of the row
    meta: dict = field(default_factory=dict)


def payload_token_indices(offs: list[tuple[int, int]], byte_spans) -> list[int]:
    """Content tokens whose byte span overlaps any payload span (zero-width tokens never do)."""
    spans = [(int(s), int(e)) for s, e in byte_spans]
    return [i for i, (a, b) in enumerate(offs) if b > a and any(a < e and b > s for s, e in spans)]


def row_attack_labels(row: dict, label_order: list[str] | None = None) -> list[str]:
    labs = set(row.get("payload_labels") or row["labels"]) - {"benign"}
    labs.add(INDIRECT)
    return sorted(labs, key=(label_order.index if label_order else None))


def label_windows(row: dict, offs: list[tuple[int, int]], text_bytes: bytes | None = None,
                  max_len: int = MAX_LEN, stride: int = STRIDE, label_order: list[str] | None = None) -> list[Window]:
    """Cut a row into gateway windows and label each one (module docstring)."""
    b = row["text"].encode("utf-8") if text_bytes is None else text_bytes
    ranges = token_ranges(len(offs), max_len, stride)
    spans = window_byte_spans(b, offs, ranges)
    benign = row["labels"] == ["benign"]
    out = []
    if row.get("byte_spans") and not benign:
        ptoks = payload_token_indices(offs, row["byte_spans"])
        attack = row_attack_labels(row, label_order)
        total = len(ptoks)
        for (s, e), (bs, be) in zip(ranges, spans):
            k = sum(1 for i in ptoks if s <= i < e)
            share = k / total if total else 0.0
            if k == 0:
                lab, why = ["benign"], "host"
            elif share >= KEEP_SHARE:
                lab, why = attack, "payload"
            elif share >= DROP_SHARE:
                lab, why = None, "partial"
            elif k <= FRAGMENT_MAX_TOKENS:
                lab, why = ["benign"], "fragment"
            else:
                lab, why = None, "partial"
            out.append(Window(s, e, bs, be, lab, why, k, share))
        return out
    for j, ((s, e), (bs, be)) in enumerate(zip(ranges, spans)):
        if benign:
            out.append(Window(s, e, bs, be, ["benign"], "row"))
        else:  # attack without spans: whole-row labels on the first window only
            out.append(Window(s, e, bs, be, list(row["labels"]) if j == 0 else None, "row" if j == 0 else "tail"))
    return out


def worst_case(probs_per_window: list[list[float]], benign_index: int = 0) -> list[float]:
    """Per-label worst case over a text's windows, as Classifier.Score: the minimum of the benign label,
    the maximum of every other label."""
    agg = list(probs_per_window[0])
    for p in probs_per_window[1:]:
        for k, v in enumerate(p):
            agg[k] = min(agg[k], v) if k == benign_index else max(agg[k], v)
    return agg
