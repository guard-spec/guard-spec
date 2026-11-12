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
  - name: guardspec-classifier-v6
    results: []
---

<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# guardspec-classifier (v6, candidate)

A small English + Vietnamese **prompt-injection risk classifier**, shipped as an INT8 ONNX model
(118.5 MB) and, for GPUs, the same checkpoint in FP16 (235.6 MB). It is the L2 layer of
[Guard Spec](https://github.com/guard-spec/guard-spec), a self-hosted prompt-injection guardrail
gateway. It is not an LLM and does not generate text.

**v6 is a candidate, not Guard Spec's default classifier** (that is v3b). Run it in Guard Spec's shadow
mode (`SHADOW_L2_MODEL=guardspec-classifier@v6`) for at least 7 days before using it. It is v5's recipe
trained on new data for long documents and tool output: every attack embedded in code, logs or prose has
a benign twin with ordinary prose in its place, there are hard negatives that *talk about* prompt
injection, and Guard Spec's long-document benchmark is kept out of training. It blocks fewer benign long
documents than v5, but not the 1% the work aimed for (see Limitations).

- Architecture: `intfloat/multilingual-e5-small` (BERT, 12 layers, hidden size 384, about 118M
  parameters) fine-tuned with an 8-label sigmoid head (multi-label).
- Labels: `benign`, `direct_injection`, `indirect_injection`, `jailbreak`, `prompt_extraction`,
  `data_exfiltration`, `tool_poisoning`, `obfuscation`.
- Risk score: **1 − sigmoid(logit_benign)**. The per-attack-label scores are advisory.
- Input: up to 256 tokens per window. Longer text is cut into windows of 254 content tokens overlapping
  by 64 and the worst window counts (Guard Spec does this; v6 was trained on exactly these windows).
  The text is passed as is (no e5 `query: ` prefix).
- Version: **v6** (2026-11-11; FP16 file 2026-11-12).

## How Guard Spec uses it

| layer | what | calibration |
|---|---|---|
| L1 | rules and patterns | built in |
| **L2** | **this classifier**, risk = 1 − p(benign) | Platt scaling: `sigmoid(A · logit(risk) + B)`, A 0.8582, B −0.2526 (FP16: A 0.8634, B −0.4518) |
| L3 | similarity to attack and benign exemplars with `multilingual-e5-small` embeddings | built in |

The calibrated layer scores are combined by a logistic regression over their logits, L1, L2, L3 weights
(0.4714, 0.9148, 0.3855), bias 0.6131 (L1 + L2 only: (0.4963, 0.9434), bias 0.4418). The gateway
**blocks at a fused score of 0.85**. `calibration.json` also sets `l2_untrusted_max` 0.88: on untrusted
content (tool results, documents) the classifier's calibrated score is capped there, so L2 alone cannot
block such content and L1 or L3 must add the rest. The cap is derived from the validation splits by
`cmd/calibrate fit`, never from the eval sets; a gateway that does not know the field ignores it, and
user messages are not capped. `thresholds.json` carries a stand-alone threshold for the classifier alone
(`risk_threshold` 0.2546, benign FPR ≤ 1% on validation); it is not the gateway's block threshold.

**FP16 (GPU option).** `model_fp16.onnx` is exported from the same FP32 model as the INT8 file, for ONNX
Runtime's CUDA execution provider (Guard Spec `INFERENCE_PROVIDER=cuda`; the CPU keeps the INT8 file).
Its decisions at 0.85 agree with the INT8 model's on 98.8% to 99.9% of rows, below the 99.5% Guard Spec
requires on two sets, so it has its own calibration: the `fp16` block of `calibration.json`, fitted on the
same validation rows, which applies only when the classifier is loaded from `model_fp16.onnx`. With it,
agreement is 99.0% to 99.9%, and on Guard Spec's `eval/data` the FP16 model's TPR at FPR ≤ 1% is 0.4 to 0.5
points above INT8's. Expect about 1% of decisions near the threshold to differ between a GPU and a CPU
gateway: the FP16 file is a closer copy of the FP32 model, not a bit-identical copy of the INT8 one.

## Files

| file | SHA-256 | |
|---|---|---|
| `model_int8.onnx` | `be5fba5b2c94fdbb20a628002cadde2857349dbb6092e3690ba41d6bcd347f29` | ONNX, INT8 dynamic quantization (QInt8 weights, per channel); 118,466,001 bytes |
| `model_fp16.onnx` | `fd7a676767cf8cfc98154cb87f60b1168b74a8a0e726c723c658974a0db06162` | ONNX, FP16 weights, FP32 inputs and `logits`; 235,629,184 bytes; for the CUDA execution provider |
| `tokenizer.json` | `6879d3648d0329c894b1cbb0c89096430e24d3c7cf5d359d4ccc87ce585c4ae4` | Hugging Face `tokenizers` file of the base model (the same file as v5's) |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` | model config with `id2label` (as v4 and v5) |
| `thresholds.json` | `c1ae128e5868f85028ac1f686a07b9e51387d971ccc8a1e967e6a1a434b751a8` | risk definition, thresholds, validation metrics |
| `calibration.json` | `ab7281b6b442c2fd970a5c7cb4f232cba37766cd3548ef4f7530aec44617625d` | Guard Spec fusion calibration, the untrusted-content cap and the FP16 block |

ONNX inputs: `input_ids` and `attention_mask` (int64, `[batch, seq]`). Output: `logits` (float32,
`[batch, 8]`) in the label order of `config.json`. The usage example of the v3b card applies unchanged
to either model file.

## Training data

Fine-tuned from `intfloat/multilingual-e5-small` (MIT, revision
`614241f622f53c4eeff9890bdc4f31cfecc418b3`) with the v5 recipe, one training example per gateway
window (50,099 rows and 52,373 windows per epoch; 12,785 validation rows). The v4 data (the v3b data:
deepset/prompt-injections, Apache-2.0; Lakera/gandalf_ignore_instructions, MIT;
jackhhao/jailbreak-classification, Apache-2.0; OpenAssistant/oasst2, Apache-2.0; nvidia/HelpSteer2,
**CC-BY-4.0**, prompts only; Guard Spec project-written rows, Apache-2.0; the v4 Vietnamese rows;
owner-supplied synthetic EN/VI rows and AI-written OTP/eKYC rows, used with consent and **not
redistributed**), plus the v6 set (`train/data/build_v6.py`, 15,785 training rows):

- every v5 source (benign code, configuration, logs and long prose of permissively licensed repositories,
  U.S. Code titles, Vietnamese laws and pre-1900 works from vi.wikisource, generated logs and terminal
  output) and attack rows embedded in such hosts at 12 positions;
- for every embedded attack a benign twin: the same host and position with documentation, comments,
  log lines or public-domain prose in the payload's place;
- hard negatives about security: documentation of permissively licensed guardrail and red-teaming
  projects (garak, llm-guard, MITRE ATLAS, NeMo Guardrails, vigil-llm, guardrails-ai, llm-security,
  llm-attacks; their code, probes and prompt collections excluded) and project-written explanatory
  security prose and human-sounding log lines in English and Vietnamese;
- no 50-token run of Guard Spec's long-document benchmark (bench/long) in any row.

**Attribution.** HelpSteer2: NVIDIA, *HelpSteer2: Open-source dataset for training top-performing
reward models* (Wang et al., 2024), CC-BY-4.0, https://huggingface.co/datasets/nvidia/HelpSteer2. Credit
also goes to deepset, Lakera, jackhhao and the upstream authors, the OpenAssistant contributors, and the
authors of the repositories and texts above (`train/DATA_LICENSES.md`, v5 and v6). Vietnamese project
rows are machine-written and were not reviewed by a native speaker. Details: `train/DATA_CARD.md` ("v6
data"), `train/DATA_LICENSES.md` and `train/MODEL_CARD.md` ("v6") in the Guard Spec repository.

## Evaluation

Gateway scores, blocking at 0.85, on the hold-out halves of Guard Spec's eval sets (held out from
training, selection and calibration, scored once) and on the owner's hold-out rows (owner-written, not
redistributed). v3b with its shipped calibration, v5 and v6 with their `calibration.json` and cap; INT8
on the CPU.

| | v3b (default) | v5 | **v6** |
|---|---|---|---|
| `eval/data` (user messages, 1,113 rows): TPR at FPR ≤ 1% / TPR and FPR at 0.85 | 0.942 / 0.9435 and 1.57% | 0.940 / 0.9435 and 1.17% | **0.964** / 0.9452 and **0.39%** |
| `eval/codelog` (benign tool output, 162 rows): FPR, code corroboration off / on | 20.99% / 7.41% | 0.62% / 0.62% | 1.23% / 1.23% |
| `eval/embedded` (attacks in code and logs), corroboration off: TPR / FPR | 0.779 / 15.1% | 0.861 / 4.7% | 0.857 / 5.1% |
| `eval/embedded`, corroboration on: TPR / FPR | 0.719 / 5.7% | 0.824 / 2.5% | 0.822 / 3.3% |
| owner hold-out (276 attacks / 184 benign): TPR / FPR at 0.85 | 0.714 / 1.6% | 0.823 / 4.3% | 0.779 / **1.1%** |
| `val_v6_holdout` (1,746 benign / 492 embedded, tool path): FPR at 0.85 / TPR at FPR ≤ 1% | 3.4% / 0.561 | 1.5% / 0.530 | **0.5%** / **0.982** |
| `val_v3_holdout` (1,173 benign / 337 generated attacks): FPR / TPR at 0.85 | 0.5% / 0.953 | 0.5% / 0.887 | 0.8% / 0.899 |
| bench/long hold-out, benign documents of 100k to 200k tokens blocked (`l1,l2`, chunks) | 10 / 18 | 3 / 18 | 2 / 18 |
| bench/long `long` profile (128 more documents of 100k to 200k tokens), blocked | 80% | 45% | 24% to 26% |
| bench/long hold-out, attacks embedded in long documents caught (384 variants) | 53.6% | 89.6% | 86.7% |

## Limitations

- **Long documents: the target is not met.** The work aimed at blocking at most 1% of benign documents
  of 100k to 200k tokens. On 128 such documents v6 blocks about one in four (a third of v3b's rate, half
  of v5's). Three later attempts did not reach the target without losing detection: a document-level
  rule on the long path, tightened L1 rules with a stricter long-path decision (6.6% of new documents
  blocked, rule changes kept in the gateway), and a further training round, which blocked no benign
  document but caught 9 points fewer embedded attacks and was not released.
- Detection of payloads embedded in long documents is a little under v5's (86.7% against 89.6%); payloads
  split far apart stay mostly undetected (59%).
- On `val_v3_holdout` it catches 0.899 of the generated attacks at the block threshold (v3b 0.953), and
  on `val_realistic_holdout` 0.887 (v3b 0.915). One of the four reported benign Vietnamese sentences is
  blocked again.
- The cap keeps an embedded attack that only the classifier recognises below the block threshold on the
  tool path, as for v5.
- Synthetic data, 256-token windows, and no content moderation, as for v3b.
