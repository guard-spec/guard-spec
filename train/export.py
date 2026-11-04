"""Export the trained classifier to ONNX, quantize it to INT8 and calibrate thresholds.

    cd train && uv run python export.py

1. torch.onnx.export of <run_dir>/best (FP32, dynamic batch and sequence axes).
2. onnxruntime dynamic quantization to INT8 (weights QInt8, per-channel).
3. Parity: max |p_int8 - p_fp32| over the validation split, and the change in
   validation AUC of the overall risk score.
4. Calibration on the validation split, using the INT8 model that ships:
   - choice of risk score (1 - p(benign) or max over attack labels), by
     validation TPR at benign FPR <= 1%;
   - the risk threshold at benign FPR <= target (config: calibration);
   - per-label thresholds (max F1 on validation, one-vs-rest).
5. Writes model_int8.onnx, tokenizer.json, config.json and thresholds.json to
   export.out_dir and prints the SHA-256 of each file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from onnxruntime.quantization import QuantType, quantize_dynamic
from sklearn.metrics import precision_recall_curve
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common_train import (ROOT, auc, label_matrix, load_config, rates, read_jsonl, risk_scores, sigmoid,
                          threshold_at_fpr, tpr_at_fpr)


def onnx_logits(sess, tok, texts, max_len, batch=64):
    out = []
    for i in range(0, len(texts), batch):
        enc = tok(texts[i:i + batch], truncation=True, max_length=max_len, padding=True, return_tensors="np")
        out.append(sess.run(["logits"], {"input_ids": enc["input_ids"].astype(np.int64),
                                         "attention_mask": enc["attention_mask"].astype(np.int64)})[0])
    return np.concatenate(out)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", help="override export.run_dir (relative to train/)")
    ap.add_argument("--data-dir", help="read the validation files (and, in train.py, the training file) from this "
                    "directory instead of data/, e.g. a GUARD_BUILD_OUT build with external rows")
    ap.add_argument("--out-dir", help="override export.out_dir (relative to train/)")
    a = ap.parse_args()
    cfg = load_config()
    if a.run_dir:
        cfg["export"]["run_dir"] = a.run_dir
    if a.data_dir:
        cfg["data"]["val"] = [f"{a.data_dir}/{Path(v).name}" for v in cfg["data"]["val"]]
        cfg["data"]["train"] = f"{a.data_dir}/{Path(cfg['data']['train']).name}"
    if a.out_dir:
        cfg["export"]["out_dir"] = a.out_dir
    labels = cfg["labels"]
    max_len = cfg["train"]["max_len"]
    run_dir = ROOT / cfg["export"]["run_dir"]
    best = run_dir / "best"
    out_dir = (ROOT / cfg["export"]["out_dir"]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    tok = AutoTokenizer.from_pretrained(best)
    model = AutoModelForSequenceClassification.from_pretrained(best).eval()

    val = [dict(r, split=Path(p).stem) for p in cfg["data"]["val"] for r in read_jsonl(ROOT / p)]
    texts = [r["text"] for r in val]
    # PyTorch reference on the first validation batch, computed before export (tracing touches the module).
    with torch.no_grad():
        enc = tok(texts[:64], truncation=True, max_length=max_len, padding=True, return_tensors="pt")
        pt = torch.sigmoid(model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).logits).numpy()

    # 1. FP32 ONNX ---------------------------------------------------------------------
    fp32 = run_dir / "model_fp32.onnx"
    dummy = tok(["export example", "a second, slightly longer export example"], padding=True, return_tensors="pt")

    class Wrapper(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, input_ids, attention_mask):
            return self.m(input_ids=input_ids, attention_mask=attention_mask).logits

    torch.onnx.export(Wrapper(model), (dummy["input_ids"], dummy["attention_mask"]), str(fp32),
                      input_names=["input_ids", "attention_mask"], output_names=["logits"],
                      dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"},
                                    "logits": {0: "batch"}},
                      opset_version=cfg["export"]["opset"], do_constant_folding=True)

    # 2. INT8 dynamic quantization ------------------------------------------------------
    int8 = out_dir / "model_int8.onnx"
    quantize_dynamic(str(fp32), str(int8), weight_type=QuantType.QInt8, per_channel=True)

    # 3. Parity on validation -------------------------------------------------------------
    y = label_matrix(val, labels)
    is_attack = 1 - y[:, 0]
    so = ort.SessionOptions()
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    s32 = ort.InferenceSession(str(fp32), so, providers=["CPUExecutionProvider"])
    s8 = ort.InferenceSession(str(int8), so, providers=["CPUExecutionProvider"])
    t = time.time()
    p32 = sigmoid(onnx_logits(s32, tok, texts, max_len))
    p8 = sigmoid(onnx_logits(s8, tok, texts, max_len))
    parity = dict(
        torch_vs_onnx_fp32_max_abs=float(np.abs(pt - p32[:64]).max()),
        int8_vs_fp32_max_abs=float(np.abs(p8 - p32).max()),
        int8_vs_fp32_mean_abs=float(np.abs(p8 - p32).mean()),
        seconds=time.time() - t,
    )

    # 4. Calibration (INT8) ----------------------------------------------------------------
    target = cfg["calibration"]["target_benign_fpr"]
    choice = {}
    for kind in ("1-p_benign", "max_attack"):
        s8k, s32k = risk_scores(p8, labels, kind), risk_scores(p32, labels, kind)
        tpr, fpr, thr = tpr_at_fpr(is_attack, s8k, target)
        choice[kind] = dict(val_auc_int8=auc(is_attack, s8k), val_auc_fp32=auc(is_attack, s32k),
                            val_tpr_at_fpr=tpr, val_fpr=fpr, threshold=thr)
    kind = max(choice, key=lambda k: (choice[k]["val_tpr_at_fpr"], choice[k]["val_auc_int8"]))
    parity["risk_auc_delta_int8_minus_fp32"] = {k: v["val_auc_int8"] - v["val_auc_fp32"] for k, v in choice.items()}
    risk = risk_scores(p8, labels, kind)
    thr = choice[kind]["threshold"]
    r32 = risk_scores(p32, labels, kind)
    parity["risk_abs_diff"] = dict(max=float(np.abs(risk - r32).max()), p99=float(np.percentile(np.abs(risk - r32), 99)),
                                   rows_over_0_1=int((np.abs(risk - r32) > 0.1).sum()))
    parity["decision_agreement_at_threshold"] = float(((risk >= thr) == (r32 >= thr)).mean())
    thr5 = threshold_at_fpr(risk[is_attack == 0], 0.05)
    per_label = {}
    for j, lb in enumerate(labels[1:], start=1):
        prec, rec, ths = precision_recall_curve(y[:, j], p8[:, j])
        f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-9)
        k = int(np.nanargmax(f1[:-1]))
        per_label[lb] = dict(threshold=float(ths[k]), val_f1=float(f1[k]), val_precision=float(prec[k]),
                             val_recall=float(rec[k]), val_auc=auc(y[:, j], p8[:, j]))
    by_lang = {}
    for name in sorted({r["split"] for r in val}):
        m = np.array([r["split"] == name for r in val])
        tpr, fpr = rates(is_attack[m], risk[m], thr)
        by_lang[name] = dict(tpr=tpr, benign_fpr=fpr, n_attack=int(is_attack[m].sum()), n_benign=int((1 - is_attack[m]).sum()))
    for lang in ("en", "vi"):
        m = np.array([r["lang"] == lang for r in val])
        tpr, fpr = rates(is_attack[m], risk[m], thr)
        by_lang[lang] = dict(tpr=tpr, benign_fpr=fpr, auc=auc(is_attack[m], risk[m]))
    thresholds = dict(
        model=cfg["name"],
        labels=labels,
        output="logits; apply sigmoid per label (multi-label head)",
        max_len=max_len,
        risk_score=kind,
        risk_score_doc=("risk = 1 - sigmoid(logit_benign)" if kind == "1-p_benign"
                        else "risk = max over attack labels of sigmoid(logit)"),
        risk_threshold=thr,
        risk_threshold_target_benign_fpr=target,
        risk_threshold_review=thr5,
        risk_threshold_review_target_benign_fpr=0.05,
        validation=dict(n=len(val), n_attack=int(is_attack.sum()), choice=choice, by_lang_at_threshold=by_lang),
        label_thresholds={lb: v["threshold"] for lb, v in per_label.items()},
        label_threshold_method="max F1 on the validation split, one-vs-rest",
        label_validation=per_label,
        calibrated_on="validation splits " + ", ".join(cfg["data"]["val"]) + ", INT8 model",
    )

    # 5. Package ---------------------------------------------------------------------------
    (out_dir / "thresholds.json").write_text(json.dumps(thresholds, indent=2) + "\n", encoding="utf-8")
    tok.save_pretrained(run_dir / "tok")
    shutil.copy(run_dir / "tok" / "tokenizer.json", out_dir / "tokenizer.json")
    shutil.copy(best / "config.json", out_dir / "config.json")
    (run_dir / "export_report.json").write_text(json.dumps(dict(parity=parity, thresholds=thresholds), indent=2) + "\n",
                                                encoding="utf-8")
    print(json.dumps(parity, indent=2))
    print(json.dumps({k: thresholds[k] for k in ("risk_score", "risk_threshold", "risk_threshold_review")}, indent=2))
    print(json.dumps(choice, indent=2))
    print(json.dumps(by_lang, indent=2))
    for f in sorted(out_dir.iterdir()):
        print(f"{sha256(f)}  {f.name}  ({f.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
