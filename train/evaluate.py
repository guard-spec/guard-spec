"""Score the eval set with the INT8 ONNX classifier and with ProtectAI's model.

    cd train && uv run python evaluate.py [--skip-compare] [--skip-latency]

Final report only: nothing here feeds back into training or calibration.

Our model is run exactly as packaged in export.out_dir (model_int8.onnx +
tokenizer.json via the `tokenizers` library + thresholds.json). Inputs longer
than max_len are split into overlapping windows and the row takes the max risk,
as the gateway's inference runner does. ProtectAI's
deberta-v3-small-prompt-injection-v2 runs through transformers (truncated at
512 tokens); its score is p(INJECTION).

Metrics per group (all, en, vi, <lang>/<category>, <lang>/variant:<v>):
  - ROC-AUC;
  - TPR at benign FPR <= 1% (threshold read off the group's own ROC curve);
  - TPR / benign FPR at the deployed threshold: our validation-calibrated risk
    threshold, ProtectAI's default 0.5.
Category groups use every benign row of the same language as negatives;
variant groups use benign rows of the same variant when there are any.

Also reports CPU latency of the INT8 model with onnxruntime (batch 1, 128 and
256 tokens) and writes reports/eval_report.{json,md}.
"""

from __future__ import annotations

import argparse
import collections
import json
import platform
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from common_train import ROOT, auc, load_config, rates, read_jsonl, sigmoid, tpr_at_fpr

EVAL = ROOT.parent / "eval" / "data"
REPORTS = ROOT / "reports"


def load_eval():
    rows = []
    for lang in ("en", "vi"):
        rows += read_jsonl(EVAL / f"{lang}.jsonl")
    return rows


# ---------------------------------------------------------------------------
# Our model (as packaged)
# ---------------------------------------------------------------------------

class Ours:
    def __init__(self, model_dir: Path, threads: int | None = None):
        self.th = json.loads((model_dir / "thresholds.json").read_text())
        self.labels = self.th["labels"]
        self.max_len = self.th["max_len"]
        self.tok = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tok.enable_truncation(max_length=self.max_len, stride=64)
        self.tok.no_padding()
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        if threads:
            so.intra_op_num_threads = threads
        self.sess = ort.InferenceSession(str(model_dir / "model_int8.onnx"), so, providers=["CPUExecutionProvider"])
        self.pad = next(i for i in (self.tok.token_to_id("[PAD]"), self.tok.token_to_id("<pad>"), 0) if i is not None)

    def windows(self, text):
        enc = self.tok.encode(text)
        return [enc] + list(enc.overflowing)

    def run_ids(self, seqs):
        n = max(len(s) for s in seqs)
        ids = np.full((len(seqs), n), self.pad, dtype=np.int64)
        mask = np.zeros((len(seqs), n), dtype=np.int64)
        for i, s in enumerate(seqs):
            ids[i, :len(s)] = s
            mask[i, :len(s)] = 1
        return self.sess.run(["logits"], {"input_ids": ids, "attention_mask": mask})[0]

    def risk(self, probs):
        if self.th["risk_score"] == "1-p_benign":
            return 1.0 - probs[:, 0]
        return probs[:, 1:].max(axis=1)

    def score(self, texts, batch=32):
        flat, owner = [], []
        for i, t in enumerate(texts):
            for w in self.windows(t):
                flat.append(w.ids)
                owner.append(i)
        order = np.argsort([len(s) for s in flat])
        probs = np.zeros((len(flat), len(self.labels)), dtype=np.float32)
        for k in range(0, len(order), batch):
            idx = order[k:k + batch]
            probs[idx] = sigmoid(self.run_ids([flat[j] for j in idx]))
        risk = self.risk(probs)
        best = {}
        for j, i in enumerate(owner):
            if i not in best or risk[j] > risk[best[i]]:
                best[i] = j
        sel = [best[i] for i in range(len(texts))]
        n_windows = collections.Counter(owner)
        return risk[sel], probs[sel], sum(1 for v in n_windows.values() if v > 1)


# ---------------------------------------------------------------------------
# ProtectAI baseline
# ---------------------------------------------------------------------------

def protectai_scores(cfg, texts):
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    cc = cfg["compare"]
    path = snapshot_download(cc["model"], revision=cc["revision"], cache_dir=str(ROOT / ".cache" / "hf"),
                             allow_patterns=["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
                                             "special_tokens_map.json", "added_tokens.json", "spm.model"])
    tok = AutoTokenizer.from_pretrained(path)
    model = AutoModelForSequenceClassification.from_pretrained(path).eval()
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    model.to(device)
    inj = [i for i, lb in model.config.id2label.items() if lb.upper() == "INJECTION"][0]
    order = np.argsort([len(t) for t in texts])
    out = np.zeros(len(texts), dtype=np.float32)
    with torch.no_grad():
        for k in range(0, len(order), 32):
            idx = order[k:k + 32]
            enc = tok([texts[i] for i in idx], truncation=True, max_length=cc["max_len"], padding=True,
                      return_tensors="pt").to(device)
            p = torch.softmax(model(**enc).logits.float(), dim=-1)[:, inj].cpu().numpy()
            out[idx] = p
    return out, dict(model=cc["model"], revision=cc["revision"], label_map=model.config.id2label)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def groups(rows):
    g = collections.defaultdict(list)
    for i, r in enumerate(rows):
        g["all"].append(i)
        g[r["lang"]].append(i)
    benign_by_lang = {lang: [i for i in g[lang] if rows[i]["label"] == "benign"] for lang in ("en", "vi")}
    cats = collections.defaultdict(list)
    variants = collections.defaultdict(list)
    for i, r in enumerate(rows):
        if r["label"] == "attack":
            cats[f"{r['lang']}/{r['category']}"].append(i)
        variants[f"{r['lang']}/variant:{r['variant']}"].append(i)
    for k, idx in sorted(cats.items()):
        g[k] = idx + benign_by_lang[k.split("/")[0]]
    for k, idx in sorted(variants.items()):
        has_benign = any(rows[i]["label"] == "benign" for i in idx)
        g[k] = idx if has_benign else idx + benign_by_lang[k.split("/")[0]]
    return g


def metrics(rows, scores, threshold):
    y = np.array([r["label"] == "attack" for r in rows])
    out = {}
    for name, idx in groups(rows).items():
        idx = np.array(sorted(set(idx)))
        yy, ss = y[idx], scores[idx]
        m = dict(n_attack=int(yy.sum()), n_benign=int((~yy).sum()))
        if yy.any() and (~yy).any():
            tpr, fpr, t = tpr_at_fpr(yy, ss, 0.01)
            m.update(auc=auc(yy, ss), tpr_at_fpr1=tpr, fpr_at_fpr1=fpr, thr_at_fpr1=t)
        tpr, fpr = rates(yy, ss, threshold)
        m.update(tpr_at_thr=tpr, fpr_at_thr=fpr)
        out[name] = m
    return out


def category_hits(rows, probs, labels, label_thr):
    """Share of eval attack rows whose eval category is predicted by its label head."""
    res = collections.defaultdict(lambda: [0, 0, 0])
    for r, p in zip(rows, probs):
        if r["label"] != "attack":
            continue
        j = labels.index(r["category"])
        top = labels[1 + int(np.argmax(p[1:]))]
        key = f"{r['lang']}/{r['category']}"
        res[key][0] += p[j] >= label_thr[r["category"]]
        res[key][1] += top == r["category"]
        res[key][2] += 1
    return {k: dict(head_fires=v[0] / v[2], top1=v[1] / v[2], n=v[2]) for k, v in sorted(res.items())}


def latency(model: Ours, model_dir: Path, threads: int | None):
    m = Ours(model_dir, threads) if threads else model
    rng = np.random.default_rng(0)
    out = {}
    for n in (128, 256):
        ids = rng.integers(1000, 200000, size=n).tolist()
        ids[0], ids[-1] = 0, 2
        for _ in range(30):
            m.run_ids([ids])
        ts = []
        for _ in range(400):
            t = time.perf_counter()
            m.run_ids([ids])
            ts.append((time.perf_counter() - t) * 1000)
        out[f"{n}_tokens"] = dict(p50_ms=float(np.percentile(ts, 50)), p99_ms=float(np.percentile(ts, 99)))
    return out


def fmt(x):
    return "-" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.3f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-compare", action="store_true")
    ap.add_argument("--skip-latency", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    model_dir = (ROOT / cfg["export"]["out_dir"]).resolve()
    rows = load_eval()
    texts = [r["text"] for r in rows]

    ours = Ours(model_dir)
    t = time.time()
    risk, probs, n_multi = ours.score(texts)
    ours_secs = time.time() - t
    report = dict(eval_rows=len(rows), ours=dict(
        model_dir=cfg["export"]["out_dir"], risk_score=ours.th["risk_score"], threshold=ours.th["risk_threshold"],
        rows_with_multiple_windows=n_multi, seconds=ours_secs,
        metrics=metrics(rows, risk, ours.th["risk_threshold"]),
        category_heads=category_hits(rows, probs, ours.labels, ours.th["label_thresholds"])))
    if not args.skip_compare:
        pscore, info = protectai_scores(cfg, texts)
        report["protectai"] = dict(info, threshold=0.5, metrics=metrics(rows, pscore, 0.5))
    if not args.skip_latency:
        report["latency_int8_cpu"] = dict(
            machine=f"{platform.machine()} {platform.processor()} {platform.platform()}",
            default_threads=latency(ours, model_dir, None), one_thread=latency(ours, model_dir, 1), note="model only, batch 1")
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "eval_report.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")

    # Markdown -------------------------------------------------------------------------
    om = report["ours"]["metrics"]
    pm = report.get("protectai", {}).get("metrics", {})
    lines = ["| group | n atk/ben | ours AUC | ours TPR@FPR≤1% | ours TPR / FPR @ cal. thr | ProtectAI AUC | ProtectAI TPR@FPR≤1% | ProtectAI TPR / FPR @0.5 |",
             "|---|---|---|---|---|---|---|---|"]
    for g, m in om.items():
        p = pm.get(g, {})
        lines.append(f"| {g} | {m['n_attack']}/{m['n_benign']} | {fmt(m.get('auc'))} | {fmt(m.get('tpr_at_fpr1'))} | "
                     f"{fmt(m['tpr_at_thr'])} / {fmt(m['fpr_at_thr'])} | {fmt(p.get('auc'))} | {fmt(p.get('tpr_at_fpr1'))} | "
                     f"{fmt(p.get('tpr_at_thr'))} / {fmt(p.get('fpr_at_thr'))} |")
    md = "\n".join(lines) + "\n"
    if "latency_int8_cpu" in report:
        md += "\nLatency (INT8 ONNX, onnxruntime CPU, batch 1, model only):\n\n| threads | 128 tok p50 / p99 ms | 256 tok p50 / p99 ms |\n|---|---|---|\n"
        for k in ("default_threads", "one_thread"):
            L = report["latency_int8_cpu"][k]
            md += (f"| {k} | {L['128_tokens']['p50_ms']:.2f} / {L['128_tokens']['p99_ms']:.2f} | "
                   f"{L['256_tokens']['p50_ms']:.2f} / {L['256_tokens']['p99_ms']:.2f} |\n")
    md += "\nCategory heads on eval attacks (head fires at its threshold / top-1 attack label = eval category):\n\n"
    md += "| group | n | head fires | top-1 |\n|---|---|---|---|\n"
    for k, v in report["ours"]["category_heads"].items():
        md += f"| {k} | {v['n']} | {v['head_fires']:.3f} | {v['top1']:.3f} |\n"
    (REPORTS / "eval_report.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
