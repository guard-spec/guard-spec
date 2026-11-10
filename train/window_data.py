"""Window-level examples for train.py and export.py (v5, RF-437128e9).

Every row is tokenized once with the base model's tokenizer.json (as the gateway loads it, see
windows.GatewayTokenizer) and cut into the gateway's windows; windows.label_windows gives each window
its labels or drops it. A model input is [CLS] + window ids + [SEP], exactly what internal/onnx feeds
the model, so a row of at most 254 tokens is the same input as before v5.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass

import numpy as np

import windows as W


def tokenizer_file(base_model: str, revision: str) -> str:
    from huggingface_hub import hf_hub_download

    return hf_hub_download(base_model, "tokenizer.json", revision=revision)


@dataclass
class Example:
    ids: np.ndarray            # content ids of the window (int32)
    y: np.ndarray | None       # label vector, None for a dropped window (scored, never trained on)
    row: int                   # index of the row in its list
    lang: str
    variant: str
    why: str
    text: str | None = None    # the window's text, kept for training-time augmentation only
    whole_row: bool = True     # the window is the whole row (one-window row)
    trunc_ok: bool = True      # an augmented text longer than a window may be truncated (whole-row labels)


def build_examples(rows, tok: W.GatewayTokenizer, labels, max_len=W.MAX_LEN, stride=W.STRIDE,
                   keep_text=lambda r: False, batch=2048):
    """Examples for every window of every row, in row order, and counts per window outcome.
    keep_text(row) says whether the window text is kept (the rows training-time augmentation may rewrite)."""
    out, stats = [], collections.Counter()
    for b0 in range(0, len(rows), batch):
        chunk = rows[b0:b0 + batch]
        encs = tok.encode_batch_offsets([r["text"] for r in chunk])
        for j, (r, (ids, offs)) in enumerate(zip(chunk, encs)):
            i = b0 + j
            tb = r["text"].encode("utf-8")
            ws = W.label_windows(r, offs, tb, max_len, stride, label_order=labels)
            spans = bool(r.get("byte_spans")) and r["labels"] != ["benign"]
            keep = keep_text(r)
            ids_a = np.asarray(ids, dtype=np.int32)
            stats["rows"] += 1
            stats["rows_multiwindow"] += len(ws) > 1
            if spans and not any(w.why == "payload" for w in ws):
                stats["embedded_rows_without_attack_window"] += 1
            for w in ws:
                stats[f"windows:{w.why}"] += 1
                y = None
                if w.labels is not None:
                    y = np.zeros(len(labels), dtype=np.float32)
                    for lb in w.labels:
                        y[labels.index(lb)] = 1.0
                out.append(Example(
                    ids=ids_a[w.start:w.end], y=y, row=i, lang=r.get("lang", ""), variant=r.get("variant", ""),
                    why=w.why, text=tb[w.byte_start:w.byte_end].decode("utf-8") if keep else None,
                    whole_row=len(ws) == 1, trunc_ok=not spans))
    return out, stats


def pad_batch(id_lists, prefix, suffix, pad_id, multiple=64):
    """[CLS] + ids + [SEP] per row, padded to a multiple of `multiple` (few distinct shapes keep the MPS
    allocator cache bounded). Returns int64 input_ids and attention_mask."""
    seqs = [list(prefix) + [int(x) for x in ids] + list(suffix) for ids in id_lists]
    n = max(len(s) for s in seqs)
    n = -(-n // multiple) * multiple
    ids = np.full((len(seqs), n), pad_id, dtype=np.int64)
    mask = np.zeros((len(seqs), n), dtype=np.int64)
    for i, s in enumerate(seqs):
        ids[i, :len(s)] = s
        mask[i, :len(s)] = 1
    return ids, mask


def aggregate_rows(n_rows, examples, probs, benign_index=0):
    """Per-row worst case over its windows (windows.worst_case, as Classifier.Score), every window counted,
    dropped ones too: the gateway scores them all."""
    agg = np.full((n_rows, probs.shape[1]), np.nan, dtype=np.float64)
    other = np.arange(probs.shape[1]) != benign_index
    for ex, p in zip(examples, probs):
        a = agg[ex.row]
        if np.isnan(a[0]):
            agg[ex.row] = p
        else:
            a[benign_index] = min(a[benign_index], p[benign_index])
            a[other] = np.maximum(a[other], p[other])
    return agg


def length_order(examples):
    """Indices sorted by window length (inference batches with little padding)."""
    return sorted(range(len(examples)), key=lambda i: len(examples[i].ids))
