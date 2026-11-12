"""Fine-tune a small multilingual encoder as a multi-label attack-risk classifier.

    cd train && uv run python train.py [--data-dir <build>] [--v5-dir <v5 build> | --v6-dir <v6 build>] [--run-dir <run>]

Reads config.yaml and data/{train,val}.jsonl, fine-tunes the pinned base
model with a sigmoid (multi-label) head, selects the best epoch on the
validation split (early stopping) and saves it with save_pretrained to
<run_dir>/best. Only that checkpoint is kept. The eval set (eval/) is never
read here.

v5 (RF-437128e9): training is window-level. Every row is cut into the
gateway's windows (256 tokens with the special tokens, 64-token overlap;
windows.py, checked against internal/onnx by a parity test) and each window
is one example, labelled from the payload spans of v5 embedded rows
(windows.label_windows). A row of at most 254 tokens is one window, the same
input as before. --v5-dir adds v5_train to training and v5_val + val_v5 to
validation (never val_v5_holdout). The best epoch's text-level validation
scores (worst window per row, as the gateway) go to <run_dir>/val_scores.jsonl
for select_v5.py. --resume continues an interrupted run from its last
finished epoch (<run_dir>/resume.pt).

v6 (RF-895d3533): --v6-dir does the same with a data/build_v6.py output
(v6_train to training, v6_val + val_v6 to validation; val_v6_holdout is never
read). The rows have the v5 shape, so nothing else changes.

v7 (RF-895d3533 R6): --v7-dir adds a data/build_v7.py output's v7_train.jsonl (benign windows of long
text, kinds v7_long, v7_hardneg and v7_gen) to training. Validation is unchanged (the v6 files), so the
v7 arms select their epoch on the same validation as the v6 reference.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, PreTrainedTokenizerFast, get_linear_schedule_with_warmup

import window_data as WD
from common_train import ROOT, auc, load_config, read_jsonl, risk_scores, seed_everything, sigmoid, tpr_at_fpr
from windows import GatewayTokenizer

sys.path.insert(0, str(ROOT / "data"))
from common import strip_diacritics, teencode_v2  # noqa: E402

V5_TRAIN = "v5_train.jsonl"
V5_VAL = ["v5_val.jsonl", "val_v5.jsonl"]  # val_v5_holdout.jsonl is never read here
V6_TRAIN = "v6_train.jsonl"
V6_VAL = ["v6_val.jsonl", "val_v6.jsonl"]  # val_v6_holdout.jsonl is never read here
V7_TRAIN = "v7_train.jsonl"


def make_augment(cfg_aug, seed):
    """v2 training-time augmentation: Vietnamese `orig` rows are rewritten without diacritics or in
    randomized teencode (common.teencode_v2, table A) with the same probability whatever their
    label, so the surface form carries no label signal. Validation rows are never augmented.
    v5: applied to the window's text (a one-window row: the row's text, as before)."""
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

    aug.rng = r
    return aug


def make_loader(gtok, examples, pad_id, content, batch_size, shuffle, seed, augment=None):
    """Batches of windows: [CLS] + ids + [SEP]. An augmented window is re-tokenized; when it no longer fits
    in one window it is truncated if its labels hold for the whole text (as training on rows did), else
    (a window of a row labelled from payload spans) the original window is used."""

    def collate(batch):
        ids_list = []
        for ex in batch:
            ids = ex.ids
            if augment is not None and ex.text is not None:
                t2 = augment(ex.text, ex.lang, ex.variant)
                if t2 != ex.text:
                    new = gtok.ids(t2)
                    if len(new) <= content or ex.trunc_ok:
                        ids = new[:content]
            ids_list.append(ids)
        ids, mask = WD.pad_batch(ids_list, gtok.prefix, gtok.suffix, pad_id)
        return dict(input_ids=torch.from_numpy(ids), attention_mask=torch.from_numpy(mask),
                    labels=torch.from_numpy(np.stack([ex.y for ex in batch])))

    g = torch.Generator()
    g.manual_seed(seed)
    return DataLoader(examples, batch_size=batch_size, shuffle=shuffle, collate_fn=collate, generator=g)


@torch.no_grad()
def predict_windows(model, gtok, examples, pad_id, device, batch=64):
    """Logits of every window (dropped ones too), batched by length."""
    model.eval()
    order = WD.length_order(examples)
    out = np.zeros((len(examples), model.config.num_labels), dtype=np.float32)
    for b0 in range(0, len(order), batch):
        idx = order[b0:b0 + batch]
        ids, mask = WD.pad_batch([examples[i].ids for i in idx], gtok.prefix, gtok.suffix, pad_id)
        logits = model(input_ids=torch.from_numpy(ids).to(device), attention_mask=torch.from_numpy(mask).to(device)).logits
        out[idx] = logits.float().cpu().numpy()
        if device.type == "mps" and (b0 // batch) % 25 == 0:
            torch.mps.empty_cache()
    return out


def window_metrics(logits, y, labels):
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


def text_metrics(rows, risk):
    """Text-level risk (worst window) per validation file: AUC and TPR at benign FPR <= 1%."""
    out = {}
    files = sorted({r["_file"] for r in rows})
    for name in ["all"] + files:
        m = np.array([name == "all" or r["_file"] == name for r in rows])
        y = np.array([r["labels"] != ["benign"] for r in rows])[m]
        s = risk[m]
        tpr, fpr, t = tpr_at_fpr(y, s, 0.01) if y.any() and (~y).any() else (float("nan"),) * 3
        out[name] = dict(n=int(m.sum()), n_attack=int(y.sum()), auc=auc(y, s), tpr_at_fpr1=tpr, fpr=fpr, threshold=t)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, help="override config seed")
    ap.add_argument("--lr", type=float, help="override train.lr")
    ap.add_argument("--epochs", type=int, help="override train.epochs")
    ap.add_argument("--label-smoothing", type=float, help="override train.label_smoothing")
    ap.add_argument("--run-dir", help="override export.run_dir (relative to train/)")
    ap.add_argument("--data-dir", help="read the validation files (and, in train.py, the training file) from this "
                    "directory instead of data/, e.g. a GUARD_BUILD_OUT build with external rows")
    ap.add_argument("--train", help="override data.train (relative to train/), e.g. a GUARD_V3_REALISTIC=0 build")
    ap.add_argument("--oversample", action="append", default=[], metavar="SOURCE/LANG/VARIANT=FACTOR",
                    help="v4: add or override a train.oversample entry (repeatable), e.g. "
                         "guard-spec:owner-supplied/vi/teencode=2")
    ap.add_argument("--v5-dir", help="v5: a data/build_v5.py output (GUARD_BUILD_OUT): v5_train.jsonl is added to "
                    "training, v5_val.jsonl and val_v5.jsonl to validation; val_v5_holdout.jsonl is never read")
    ap.add_argument("--v6-dir", help="v6: a data/build_v6.py output: v6_train.jsonl is added to training, v6_val.jsonl "
                    "and val_v6.jsonl to validation; val_v6_holdout.jsonl is never read")
    ap.add_argument("--v7-dir", help="v7: a data/build_v7.py output: v7_train.jsonl is added to training "
                    "(validation unchanged)")
    ap.add_argument("--oversample-kind", action="append", default=[], metavar="KIND=FACTOR",
                    help="v5: repeat training rows of a v5 `kind` (repeatable), e.g. log_vi_repeat=2 (arm C); "
                         "v6: twin=2 (arm B), secdoc_en=2 (arm C)")
    ap.add_argument("--resume", action="store_true", help="continue from <run_dir>/resume.pt (last finished epoch)")
    ap.add_argument("--max-steps", type=int, help="smoke run: stop each epoch after this many steps")
    ap.add_argument("--subset", type=int, help="smoke run: a seeded sample of this many training rows "
                    "(validation: a quarter as many)")
    a = ap.parse_args()
    cfg = load_config()
    tc = cfg["train"]
    if a.seed is not None:
        cfg["seed"] = a.seed
    for k in ("lr", "epochs", "label_smoothing"):
        if getattr(a, k) is not None:
            tc[k] = getattr(a, k)
    if a.run_dir:
        cfg["export"]["run_dir"] = a.run_dir
    if a.data_dir:
        cfg["data"]["val"] = [f"{a.data_dir}/{Path(v).name}" for v in cfg["data"]["val"]]
        cfg["data"]["train"] = f"{a.data_dir}/{Path(cfg['data']['train']).name}"
    if a.train:
        cfg["data"]["train"] = a.train
    for spec in a.oversample:
        key, factor = spec.rsplit("=", 1)
        tc.setdefault("oversample", {})[key] = int(factor)
    for spec in a.oversample_kind:
        key, factor = spec.rsplit("=", 1)
        tc.setdefault("oversample_kind", {})[key] = int(factor)
    train_files = [cfg["data"]["train"]]
    if a.v5_dir:
        train_files.append(f"{a.v5_dir}/{V5_TRAIN}")
        cfg["data"]["val"] = cfg["data"]["val"] + [f"{a.v5_dir}/{v}" for v in V5_VAL]
    if a.v6_dir:
        train_files.append(f"{a.v6_dir}/{V6_TRAIN}")
        cfg["data"]["val"] = cfg["data"]["val"] + [f"{a.v6_dir}/{v}" for v in V6_VAL]
    if a.v7_dir:
        train_files.append(f"{a.v7_dir}/{V7_TRAIN}")
    cfg["data"]["train_files"] = train_files
    seed_everything(cfg["seed"])
    labels = cfg["labels"]
    device = torch.device(tc["device"] if (tc["device"] != "mps" or torch.backends.mps.is_available()) else "cpu")
    run_dir = ROOT / cfg["export"]["run_dir"]
    run_dir.mkdir(parents=True, exist_ok=True)
    max_len, stride = tc["max_len"], tc.get("stride", 64)
    content = max_len - 2

    train_rows = [r for p in train_files for r in read_jsonl(ROOT / p)]
    # v3: repeat some training rows every epoch, keyed "<source>/<lang>/<variant>" -> factor (config
    # train.oversample), e.g. the realistic formal Vietnamese rows. Validation rows are never repeated.
    for key, factor in (tc.get("oversample") or {}).items():
        src, lang, variant = key.rsplit("/", 2)
        extra = [r for r in train_rows if (r["source"], r["lang"], r["variant"]) == (src, lang, variant)]
        train_rows += extra * (int(factor) - 1)
        print(f"oversample {key} x{factor}: +{len(extra) * (int(factor) - 1)} rows", flush=True)
    for kind, factor in (tc.get("oversample_kind") or {}).items():  # v5: by `kind` (arm C: log_vi_repeat)
        extra = [r for r in train_rows if r.get("kind") == kind]
        train_rows += extra * (int(factor) - 1)
        print(f"oversample kind {kind} x{factor}: +{len(extra) * (int(factor) - 1)} rows", flush=True)
    val_rows = [dict(r, _file=Path(p).stem) for p in cfg["data"]["val"] for r in read_jsonl(ROOT / p)]
    if a.subset:
        rs = random.Random(f"{cfg['seed']}:subset")
        train_rows = rs.sample(train_rows, min(a.subset, len(train_rows)))
        val_rows = rs.sample(val_rows, min(max(a.subset // 4, 1), len(val_rows)))

    # The base model's tokenizer.json as is (the file the gateway runs). transformers 5 AutoTokenizer rebuilds the
    # XLM-R normalizer and pre-tokenizer instead, which tokenizes some whitespace differently.
    tok = PreTrainedTokenizerFast.from_pretrained(cfg["base_model"], revision=cfg["base_revision"])
    gtok = GatewayTokenizer(WD.tokenizer_file(cfg["base_model"], cfg["base_revision"]))
    pad_id = tok.pad_token_id
    t_prep = time.time()
    tr_ex, tr_stats = WD.build_examples(train_rows, gtok, labels, max_len, stride,
                                        keep_text=lambda r: r.get("lang") == "vi" and r.get("variant") == "orig")
    va_ex, va_stats = WD.build_examples(val_rows, gtok, labels, max_len, stride)
    tr_ex = [e for e in tr_ex if e.y is not None]
    va_lab = [i for i, e in enumerate(va_ex) if e.y is not None]
    y_va = np.stack([va_ex[i].y for i in va_lab])
    print(f"windows: train {len(tr_ex)} from {len(train_rows)} rows {dict(tr_stats)}; val {len(va_lab)} labelled of "
          f"{len(va_ex)} from {len(val_rows)} rows {dict(va_stats)} ({time.time() - t_prep:.0f}s)", flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        cfg["base_model"], revision=cfg["base_revision"], num_labels=len(labels),
        problem_type="multi_label_classification",
        id2label=dict(enumerate(labels)), label2id={lb: i for i, lb in enumerate(labels)},
    ).to(device)

    augment = make_augment(tc.get("augment"), cfg["seed"])
    tr_loader = make_loader(gtok, tr_ex, pad_id, content, tc["batch_size"], True, cfg["seed"], augment=augment)

    no_decay = ("bias", "LayerNorm.weight")
    params = [
        {"params": [p for n, p in model.named_parameters() if not n.endswith(no_decay)], "weight_decay": tc["weight_decay"]},
        {"params": [p for n, p in model.named_parameters() if n.endswith(no_decay)], "weight_decay": 0.0},
    ]
    opt = torch.optim.AdamW(params, lr=tc["lr"])
    steps_per_epoch = len(tr_loader) if not a.max_steps else min(len(tr_loader), a.max_steps)
    total = steps_per_epoch * tc["epochs"]
    sched = get_linear_schedule_with_warmup(opt, int(tc["warmup_ratio"] * total), total)
    lossf = torch.nn.BCEWithLogitsLoss()
    eps = float(tc.get("label_smoothing") or 0.0)

    log = dict(config=cfg, device=str(device), n_train_rows=len(train_rows), n_train=len(tr_ex),
               n_val_rows=len(val_rows), n_val=len(va_lab), n_val_windows=len(va_ex),
               train_windows=dict(tr_stats), val_windows=dict(va_stats), epochs=[])
    best, best_key, bad, best_scores, start_epoch = None, (-math.inf, -math.inf), 0, None, 1
    resume_path = run_dir / "resume.pt"
    if a.resume and resume_path.exists():
        st = torch.load(resume_path, map_location="cpu", weights_only=False)
        model.load_state_dict(st["model"])
        opt.load_state_dict(st["opt"])
        sched.load_state_dict(st["sched"])
        tr_loader.generator.set_state(st["loader_rng"])
        if augment is not None:
            augment.rng.setstate(st["augment_rng"])
        torch.set_rng_state(st["torch_rng"])
        random.setstate(st["py_rng"])
        np.random.set_state(st["np_rng"])
        best, best_key, bad, best_scores = st["best"], tuple(st["best_key"]), st["bad"], st["best_scores"]
        log["epochs"], log["best_epoch"] = st["epochs"], st.get("best_epoch")
        start_epoch = st["epoch"] + 1
        print(f"resumed after epoch {st['epoch']} from {resume_path}", flush=True)
        if st.get("stopped"):
            start_epoch = tc["epochs"] + 1
    stopped = False
    for epoch in range(start_epoch, tc["epochs"] + 1):
        model.train()
        te, run_loss, n_steps = time.time(), 0.0, 0
        for step, batch in enumerate(tr_loader, 1):
            if a.max_steps and step > a.max_steps:
                break
            labels_t = batch.pop("labels").to(device)
            out = model(**{k: v.to(device) for k, v in batch.items()})
            if eps:  # v3: label smoothing of the training targets only
                labels_t = labels_t * (1 - eps) + eps / 2
            loss = lossf(out.logits, labels_t)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), tc["grad_clip"])
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            run_loss += loss.item()
            n_steps = step
            if device.type == "mps" and step % 25 == 0:
                torch.mps.empty_cache()
            if step % (100 if not a.max_steps else 20) == 0:
                print(f"epoch {epoch} step {step}/{steps_per_epoch} loss {run_loss / step:.4f} "
                      f"({time.time() - te:.0f}s, {(time.time() - te) / step:.3f}s/step, "
                      f"mps {torch.mps.driver_allocated_memory() / 1e9 if device.type == 'mps' else 0:.1f} GB)",
                      flush=True)
        train_seconds = time.time() - te
        tv = time.time()
        logits = predict_windows(model, gtok, va_ex, pad_id, device)
        lab_logits = logits[va_lab]
        val_loss = float(lossf(torch.from_numpy(lab_logits), torch.from_numpy(y_va)).item())
        m = window_metrics(lab_logits, y_va, labels)
        agg = WD.aggregate_rows(len(val_rows), va_ex, sigmoid(logits), labels.index("benign"))
        risk = 1.0 - agg[:, labels.index("benign")]
        tm = text_metrics(val_rows, risk)
        # Selection on validation loss: TPR at 1% FPR on ~2k benign rows hinges on a handful of rows
        # and swung 0.70-0.96 between epochs in the first v1 run; loss is stable.
        key = (-val_loss, max(m["1-p_benign"]["tpr_at_fpr1"], m["max_attack"]["tpr_at_fpr1"]))
        entry = dict(epoch=epoch, train_loss=run_loss / max(n_steps, 1), val_loss=val_loss, seconds=train_seconds,
                     val_seconds=time.time() - tv, steps=n_steps, **m, text=tm)
        log["epochs"].append(entry)
        print(json.dumps({k: entry[k] for k in ("epoch", "train_loss", "val_loss", "seconds", "val_seconds", "macro_auc",
                                                 "1-p_benign")} | {"text": {k: v for k, v in tm.items()}}), flush=True)
        if key > best_key:
            best_key, bad = key, 0
            best = {k: v.detach().to("cpu", copy=True) for k, v in model.state_dict().items()}
            best_scores = [dict(file=r["_file"], id=r["id"], labels=r["labels"], lang=r.get("lang"),
                                variant=r.get("variant"), kind=r.get("kind"), position=r.get("position"),
                                risk=float(risk[i]), probs=[round(float(x), 6) for x in agg[i]])
                           for i, r in enumerate(val_rows)]
            log["best_epoch"] = epoch
        else:
            bad += 1
            if bad > tc["early_stopping_patience"]:
                print(f"early stopping after epoch {epoch}")
                stopped = True
        torch.save(dict(epoch=epoch, model=model.state_dict(), opt=opt.state_dict(), sched=sched.state_dict(),
                        loader_rng=tr_loader.generator.get_state(),
                        augment_rng=augment.rng.getstate() if augment is not None else None,
                        torch_rng=torch.get_rng_state(), py_rng=random.getstate(), np_rng=np.random.get_state(),
                        best=best, best_key=list(best_key), bad=bad, best_scores=best_scores, epochs=log["epochs"],
                        best_epoch=log.get("best_epoch"), stopped=stopped), resume_path)
        if stopped:
            break
    log["train_seconds"] = sum(e["seconds"] + e.get("val_seconds", 0) for e in log["epochs"])  # resumed epochs included
    model.load_state_dict(best)
    model.to("cpu").save_pretrained(run_dir / "best")
    tok.save_pretrained(run_dir / "best")
    with open(run_dir / "val_scores.jsonl", "w", encoding="utf-8") as f:
        for s in best_scores:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    (run_dir / "train_log.json").write_text(json.dumps(log, indent=2, default=str) + "\n", encoding="utf-8")
    resume_path.unlink(missing_ok=True)  # the run is complete; best/ is the checkpoint
    print(f"best epoch {log['best_epoch']}, training time {log['train_seconds'] / 60:.1f} min")


if __name__ == "__main__":
    main()
