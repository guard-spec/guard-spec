"""Write hold-out and probe splits in the eval-set row format, so the gateway path can score them.

    cd train && uv run python holdout_evalset.py --data-dir <GUARD_BUILD_OUT> [--v5-dir <GUARD_V5_OUT>] \
        [--splits a,b] --out <dir outside the repo>
    go run -tags onnx ./cmd/eval -detector fusion-ml -data <dir> -scores <scores.jsonl>   # L2_MODEL_DIR=...

v4: hold-outs and probes are scored with `cmd/eval` (fused L1+L2+L3, the model's calibration, the L1
floor), the same code as the gateway, then tabulated by select_report.py. v5: `--v5-dir` adds `val_v5_holdout`
(code and log hosts; score it on the tool path, `cmd/eval -path tool`); `--splits` limits the output to the
splits named. The output may hold owner rows
(user_holdout), so it must go to a directory outside the repository. eval/ is never read or written.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common_train import ROOT
from select_report import HOLD_SPLITS, read_jsonl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--v5-dir", help="v5 build directory: also write val_v5_holdout.jsonl")
    ap.add_argument("--splits", help="comma-separated subset of the splits to write (default: all present)")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    repo = ROOT.parent.resolve()
    assert repo not in out.parents and out != repo, "--out must be outside the repository"
    out.mkdir(parents=True, exist_ok=True)
    splits = [(sp, Path(a.data_dir) / f"{sp}.jsonl") for sp in HOLD_SPLITS]
    if a.v5_dir:
        splits.append(("val_v5_holdout", Path(a.v5_dir) / "val_v5_holdout.jsonl"))
    only = set(a.splits.split(",")) if a.splits else None
    for sp, p in splits:
        if not p.exists() or (only is not None and sp not in only):
            continue
        with open(out / f"{sp}.jsonl", "w", encoding="utf-8") as f:
            for r in read_jsonl(p):
                attack = r["labels"] != ["benign"]
                f.write(json.dumps(dict(id=r["id"], text=r["text"], label="attack" if attack else "benign",
                                        category=r["labels"][0] if attack else "benign", lang=r["lang"],
                                        variant=r["variant"], source=r["source"], license=r["license"]),
                                   ensure_ascii=False) + "\n")
        print(sp, "->", out / f"{sp}.jsonl")


if __name__ == "__main__":
    main()
