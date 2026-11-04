"""Fine-tune a small multilingual encoder as a multi-label attack-risk classifier.

    cd train && uv run python train.py

Reads config.yaml and data/{train,val}.jsonl, fine-tunes the pinned base
model with a sigmoid (multi-label) head, selects the best epoch on the
validation split (early stopping) and saves it with save_pretrained to
<run_dir>/best. Only that checkpoint is kept. The eval set (eval/) is never
read here.
"""

from __future__ import annotations

import json
import math
import random
import sys
import time

import numpy as np
import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

from common_train import ROOT, auc, label_matrix, load_config, read_jsonl, risk_scores, seed_everything, sigmoid, tpr_at_fpr

sys.path.insert(0, str(ROOT / "data"))
from common import strip_diacritics, teencode_v2  # noqa: E402


def make_augment(cfg_aug, seed):
    """v2 training-time augmentation: Vietnamese `orig` rows are rewritten without diacritics or in
    randomized teencode (common.teencode_v2, table A) with the same probability whatever their
    label, so the surface form carries no label signal. Validation rows are never augmented."""
    if not cfg_aug:
        return None
    p_nd, p_teen = cfg_aug.get("vi_no_diacritics", 0.0), cfg_aug.get("vi_teencode", 0.0)
    r = random.Random(f"{seed}:augment")

    def aug(text, lang, variant):
        if lang != "vi" or variant != "orig":
            return text
        u = r.random()
        if u < p_nd:
            return strip_diacritics(text)
        if u < p_nd + p_teen:
            return teencode_v2(text, f"aug:{r.getrandbits(32)}", "A")
        return text

    return aug


def make_loader(tok, rows, y, max_len, batch_size, shuffle, seed, augment=None):
    data = [(r["text"], y[i], r.get("lang"), r.get("variant")) for i, r in enumerate(rows)]

    def collate(batch):
        texts = [t if augment is None else augment(t, lang, var) for t, _, lang, var in batch]
        enc = tok(texts, truncation=True, max_length=max_len, padding=True, pad_to_multiple_of=64,
                  return_tensors="pt")  # few distinct shapes keep the MPS allocator cache bounded
        enc["labels"] = torch.tensor(np.stack([lb for _, lb, _, _ in batch]))
        return enc

    g = torch.Generator()
    g.manual_seed(seed)
    return DataLoader(data, batch_size=batch_size, shuffle=shuffle, collate_fn=collate, generator=g)


@torch.no_grad()
def predict(model, loader, device):
    model.eval()
    logits, losses = [], []
    lossf = torch.nn.BCEWithLogitsLoss()
    for batch in loader:
        labels = batch.pop("labels").to(device)
        out = model(**{k: v.to(device) for k, v in batch.items()})
        losses.append(lossf(out.logits.float(), labels).item() * len(labels))
        logits.append(out.logits.float().cpu().numpy())
    logits = np.concatenate(logits)
    return logits, sum(losses) / len(logits)


def val_metrics(logits, y, labels):
    probs = sigmoid(logits)
    is_attack = 1 - y[:, 0]
    m = {}
    for kind in ("1-p_benign", "max_attack"):
        s = risk_scores(probs, labels, kind)
        tpr, fpr, t = tpr_at_fpr(is_attack, s, 0.01)
        m[kind] = dict(auc=auc(is_attack, s), tpr_at_fpr1=tpr, fpr=fpr, threshold=t)
    m["per_label_auc"] = {lb: auc(y[:, j], probs[:, j]) for j, lb in enumerate(labels)}
    m["macro_auc"] = float(np.nanmean(list(m["per_label_auc"].values())))
    return m


def main():
    cfg = load_config()
    tc = cfg["train"]
    seed_everything(cfg["seed"])
    labels = cfg["labels"]
    device = torch.device(tc["device"] if (tc["device"] != "mps" or torch.backends.mps.is_available()) else "cpu")
    run_dir = ROOT / cfg["export"]["run_dir"]
    run_dir.mkdir(parents=True, exist_ok=True)

    train_rows = read_jsonl(ROOT / cfg["data"]["train"])
    val_rows = [r for p in cfg["data"]["val"] for r in read_jsonl(ROOT / p)]
    y_tr, y_va = label_matrix(train_rows, labels), label_matrix(val_rows, labels)

    tok = AutoTokenizer.from_pretrained(cfg["base_model"], revision=cfg["base_revision"])
    model = AutoModelForSequenceClassification.from_pretrained(
        cfg["base_model"], revision=cfg["base_revision"], num_labels=len(labels),
        problem_type="multi_label_classification",
        id2label=dict(enumerate(labels)), label2id={lb: i for i, lb in enumerate(labels)},
    ).to(device)

    tr_loader = make_loader(tok, train_rows, y_tr, tc["max_len"], tc["batch_size"], True, cfg["seed"],
                            augment=make_augment(tc.get("augment"), cfg["seed"]))
    va_loader = make_loader(tok, val_rows, y_va, tc["max_len"], 64, False, cfg["seed"])

    no_decay = ("bias", "LayerNorm.weight")
    params = [
        {"params": [p for n, p in model.named_parameters() if not n.endswith(no_decay)], "weight_decay": tc["weight_decay"]},
        {"params": [p for n, p in model.named_parameters() if n.endswith(no_decay)], "weight_decay": 0.0},
    ]
    opt = torch.optim.AdamW(params, lr=tc["lr"])
    total = len(tr_loader) * tc["epochs"]
    sched = get_linear_schedule_with_warmup(opt, int(tc["warmup_ratio"] * total), total)
    lossf = torch.nn.BCEWithLogitsLoss()

    log = dict(config=cfg, device=str(device), n_train=len(train_rows), n_val=len(val_rows), epochs=[])
    best, best_key, bad = None, (-math.inf, -math.inf), 0
    t0 = time.time()
    for epoch in range(1, tc["epochs"] + 1):
        model.train()
        te, run_loss = time.time(), 0.0
        for step, batch in enumerate(tr_loader, 1):
            labels_t = batch.pop("labels").to(device)
            out = model(**{k: v.to(device) for k, v in batch.items()})
            loss = lossf(out.logits, labels_t)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), tc["grad_clip"])
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            run_loss += loss.item()
            if device.type == "mps" and step % 25 == 0:
                torch.mps.empty_cache()
            if step % 100 == 0:
                print(f"epoch {epoch} step {step}/{len(tr_loader)} loss {run_loss / step:.4f} "
                      f"({time.time() - te:.0f}s, mps {torch.mps.driver_allocated_memory() / 1e9 if device.type == 'mps' else 0:.1f} GB)",
                      flush=True)
        logits, val_loss = predict(model, va_loader, device)
        m = val_metrics(logits, y_va, labels)
        # Selection on validation loss: TPR at 1% FPR on ~2k benign rows hinges on a handful of rows
        # and swung 0.70-0.96 between epochs in the first v1 run; loss is stable.
        key = (-val_loss, max(m["1-p_benign"]["tpr_at_fpr1"], m["max_attack"]["tpr_at_fpr1"]))
        entry = dict(epoch=epoch, train_loss=run_loss / len(tr_loader), val_loss=val_loss, seconds=time.time() - te, **m)
        log["epochs"].append(entry)
        print(json.dumps({k: entry[k] for k in ("epoch", "train_loss", "val_loss", "seconds", "macro_auc",
                                                 "1-p_benign", "max_attack")}), flush=True)
        if key > best_key:
            best_key, bad = key, 0
            best = {k: v.detach().to("cpu", copy=True) for k, v in model.state_dict().items()}
            log["best_epoch"] = epoch
        else:
            bad += 1
            if bad > tc["early_stopping_patience"]:
                print(f"early stopping after epoch {epoch}")
                break
    log["train_seconds"] = time.time() - t0
    model.load_state_dict(best)
    model.to("cpu").save_pretrained(run_dir / "best")
    tok.save_pretrained(run_dir / "best")
    (run_dir / "train_log.json").write_text(json.dumps(log, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"best epoch {log['best_epoch']}, training time {log['train_seconds'] / 60:.1f} min")


if __name__ == "__main__":
    main()
