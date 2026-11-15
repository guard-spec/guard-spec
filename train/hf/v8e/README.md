---
license: apache-2.0
language: [en, vi]
pipeline_tag: text-classification
base_model: intfloat/multilingual-e5-small
library_name: onnx
tags:
  - prompt-injection
  - jailbreak
  - guardrail
  - llm-security
  - onnx
  - int8
  - fp16
  - multilingual
  - vietnamese
model-index:
  - name: guardspec-classifier-v8e
    results: []
---

<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# guardspec-classifier (v8e, candidate)

A small English + Vietnamese **prompt-injection risk classifier**. It ships as an INT8 ONNX model (118.5 MB) and,
for GPUs, as the same checkpoint in FP16 (235.6 MB). It is the L2 layer of
[Guard Spec](https://github.com/guard-spec/guard-spec), a self-hosted prompt-injection guardrail gateway. It is not
an LLM and does not generate text.

**v8e is a candidate, not Guard Spec's default classifier** (that is v3b). Run it in Guard Spec's shadow mode
(`SHADOW_L2_MODEL=guardspec-classifier@v8e`) before relying on it.

It targets benign long documents (100k to 200k tokens), which earlier versions blocked too often. Two things change:
- **Training data.** It adds pairs of benign long-text windows and attack windows cut from the same hosts, so that
  long prose alone is no longer a benign signal (Guard Spec's round R7, arm E).
- **A long-path decision in `calibration.json`.** In a text of more than 30 windows, a window blocks only if:
  - an L1 rule of raw weight 0.75 or more agrees, or a floor applied; and
  - the classifier's calibrated score is at least 0.95.

On a fresh holdout of 602 such documents, scored once, it blocked 1 (see Evaluation).

- **Architecture:** `intfloat/multilingual-e5-small` (BERT, 12 layers, hidden size 384, about 118M parameters),
  fine-tuned with an 8-label sigmoid head (multi-label).
- **Labels:** `benign`, `direct_injection`, `indirect_injection`, `jailbreak`, `prompt_extraction`,
  `data_exfiltration`, `tool_poisoning`, `obfuscation`.
- **Risk score:** **1 − sigmoid(logit_benign)**. The per-attack-label scores are advisory.
- **Input:** up to 256 tokens per window.
  - Longer text is cut into windows of 254 content tokens that overlap by 64, as in v6.
  - The text is passed as is, with no e5 `query: ` prefix.
- **Version:** **v8e**, trained 2026-11-13. The long-path decision was measured on 2026-11-14, and the FP16 file was
  exported on 2026-11-15.

## How Guard Spec uses it

| layer | what | calibration |
|---|---|---|
| L1 | rules and patterns | built in |
| **L2** | **this classifier**, risk = 1 − p(benign) | Platt scaling: `sigmoid(A · logit(risk) + B)`, A 0.8293, B −0.3497 (FP16: A 0.8422, B −0.6727) |
| L3 | similarity to attack and benign exemplars with `multilingual-e5-small` embeddings | built in |

The calibrated layer scores are combined by a logistic regression over their logits:
- L1, L2, L3 weights (0.4347, 0.9182, 0.2659), bias 0.4919;
- L1 and L2 only: weights (0.4440, 0.9430), bias 0.3805.

The gateway **blocks at a fused score of 0.85**.

`calibration.json` sets `l2_untrusted_max` 0.88, as for v6. On untrusted content the classifier's calibrated score is
capped there, so L2 alone cannot block such content.

**`long_doc` in `calibration.json`.** This is the long-path decision described above:

```json
{"min_windows": 30, "corroborate_l1": 0.75, "min_l2": 0.95, "base": 0.85}
```

A gateway older than this model ignores the fields it does not know. It would then decide long texts by their
strongest window, which blocks many more benign documents (see Evaluation, decision `base`). Use a Guard Spec
release that reads `corroborate_l1` and `min_l2`.

**FP16 (GPU option).** `model_fp16.onnx` is exported from the same FP32 model as the INT8 file, for ONNX Runtime's
CUDA execution provider. Its own calibration is the `fp16` block of `calibration.json`. It was fitted on the same
validation rows, and it keeps the same `long_doc`.

On the CPU, with its own calibration, its decisions at 0.85 agree with the INT8 model's on:
- 99.13% of `eval/data` rows (19 of 2,176 differ);
- 99.80% of `val_v3` rows (1 of 508 differs).

On all `eval/data` rows:
- TPR at FPR ≤ 1% is 0.951, against 0.952 for INT8;
- at 0.85, FP16 catches 0.937 of attacks against INT8's 0.929, and blocks 4 benign rows of 1,005 against 2.

The long-path rule was measured with INT8. For FP16 on the long path, see `fp16_agreement_v8e.md` before relying on
it.

## Files

| file | SHA-256 | |
|---|---|---|
| `model_int8.onnx` | `447c63cd6f2378c957b3282a1d4526f00feef9153e0046203c10fb20d75d7dde` | ONNX, INT8 dynamic quantization; 118,466,001 bytes |
| `model_fp16.onnx` | `601bdd4d1c1ae3666acb509445e870fb51bd0c30f6a35ff344f417c5e2dbb4ce` | ONNX, FP16 weights, FP32 inputs and `logits`; 235,629,184 bytes; for the CUDA execution provider |
| `tokenizer.json` | `6879d3648d0329c894b1cbb0c89096430e24d3c7cf5d359d4ccc87ce585c4ae4` | Hugging Face `tokenizers` file of the base model (the same file as v6's) |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` | model config with `id2label` (as v6) |
| `thresholds.json` | `dd3ce3a3d05e42b3c367dc3fb047f3c86fdde8d8b51be6d7d3ff819fc1c36bbf` | risk definition, thresholds, validation metrics |
| `calibration.json` | `3419798d34eb3ba094747d3cef1fe1c68183087e0b15ce394813e2a00e845da6` | Guard Spec fusion calibration, the untrusted-content cap, `long_doc` and the FP16 block |

**ONNX inputs:** `input_ids` and `attention_mask` (int64, `[batch, seq]`).
**Output:** `logits` (float32, `[batch, 8]`) in the label order of `config.json`.

## Training data

Fine-tuned from `intfloat/multilingual-e5-small` (MIT, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`). The
recipe is v6's: one example per gateway window, seed 20261105, 5 epochs, and the epoch selected on the v6
validation files (12,785 rows).

The data is v6's training data plus `v8e_train.jsonl` (16,906 rows, `train/data/build_v8.py`):
- 11,270 attack rows: v6 attack payloads embedded in long hosts (code, logs, prose) at placements weighted to
  mid-prose and to payloads split across windows;
- 5,636 benign rows: windows cut from the same hosts, a seeded half of the v8 benign rows.

No row shares a 50-token run with Guard Spec's long-document benchmark (bench/long, every profile up to `long7`), its
attack documents, or any eval or hold-out row.

Licenses and attribution are as for v6: deepset, Lakera, jackhhao, OpenAssistant, NVIDIA HelpSteer2 (CC-BY-4.0), and
the repositories and texts listed in `train/DATA_LICENSES.md`. The owner-supplied rows are used with consent and are
not redistributed. Details are in `train/DATA_CARD.md` ("v8 data") and `train/MODEL_CARD.md` ("R7", "R8a").

## Evaluation

All scores are INT8 on the CPU, through Guard Spec's gateway path.

**Long documents.** Fresh holdout `long8`, pinned before scoring and scored once on 2026-11-14:
- 602 benign documents of 100k and 200k tokens, English and Vietnamese, from sources no earlier profile or training
  row used;
- 324 documents with an embedded attack, using 48 payloads never used before.

| | **v8e**, with its `long_doc` | v8e, no long-path decision (`base`) | v6, the released candidate (`strong75`) |
|---|---|---|---|
| benign 100k documents blocked | **0 / 302** (CP95 upper 1.2%) | 6 / 302 | 10 / 302 |
| benign 200k documents blocked | **1 / 300** (CP95 upper 1.8%) | 14 / 300 | 14 / 300 |
| embedded attacks caught | **88.0%** (285 / 324) | 92.0% | 86.7% |
| the same payloads alone | 91.7% | 91.7% | 91.7% |

**User messages.** `eval/data` hold-out half: 602 attacks and 511 benign rows. This slice was also read in earlier
rounds, so it is not fresh.

| | v8e | v6 |
|---|---|---|
| TPR at FPR ≤ 1% | 0.962 | 0.964 |
| TPR / FPR at 0.85 | 0.937 / **0.0%** | 0.945 / 0.39% |

Reports: `train/reports/r8a_holdout.md`, `v8e_short_holdout.md`, `v8e_parity.md` (the gateway's decision matches the evaluation script on
all 790 dev documents), and `fp16_agreement_v8e.md`.

## Limitations

- **One holdout, one seed.** "At most 1% of benign long documents blocked" is supported by 602 documents. It is not
  proven for every kind of document.
  - Every benign long document v8e blocked or nearly blocked was Vietnamese.
- **The L2 bar trades some detection.** Embedded attacks that the classifier is not sure of get through more often:
  - at the end of a document: 82%;
  - split across two adjacent windows: 81%.
- **Short prompts.** On a fresh short-prompt holdout (`short1`, real-world prompts and emails, scored once;
  `v8e_short_holdout.md`), v8e does not meet the bar for replacing v3b:
  - It catches as many in-the-wild jailbreaks (75.0% against 76.2%; 92.6% against 90.6% after a label audit).
  - It blocks fewer Vietnamese benign prompts (0.5% against 2.2%).
  - It catches fewer email injections on the tool path (12.0% against 27.8%), mostly because of the
    `l2_untrusted_max` cap.
  - Like every Guard Spec model, it blocks many persona and role-play system prompts (15.6% after the audit) and
    catches few adaptive email injections (under 30%).
- **FP16 differs from INT8 near the threshold.** Measure the GPU path on your own traffic before relying on it.
- **Guard Spec's sanitizer.** Technical documents that mention `<textarea>` many times are rejected before
  classification, and text after a mention of `<script>` or `<style>` is dropped. The sanitizer, not this model,
  does this; it is tracked as a separate fix.
- Synthetic data, 256-token windows, and no content moderation, as for v6.
