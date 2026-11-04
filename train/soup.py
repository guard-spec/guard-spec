"""Average the weights of several fine-tuned checkpoints of the same base model (a uniform "model soup").

    cd train && uv run python soup.py --out runs/soup/best runs/r1/best runs/r2/best ...

v3: the runs differ only in seed (same base model, data and recipe), so their weights can be averaged.
The averaged checkpoint is written with save_pretrained, with the tokenizer of the first run, and is
exported like any run (`export.py --run-dir runs/soup`). Nothing here reads eval/.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("runs", nargs="+")
    a = ap.parse_args()
    models = [AutoModelForSequenceClassification.from_pretrained(p) for p in a.runs]
    sd = models[0].state_dict()
    avg = {}
    for k, v in sd.items():
        if v.is_floating_point():
            avg[k] = sum(m.state_dict()[k] for m in models) / len(models)
        else:
            avg[k] = v
    models[0].load_state_dict(avg)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    models[0].save_pretrained(out)
    AutoTokenizer.from_pretrained(a.runs[0]).save_pretrained(out)
    print(f"averaged {len(models)} checkpoints into {out}")


if __name__ == "__main__":
    main()
