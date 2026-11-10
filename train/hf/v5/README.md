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
  - multilingual
  - vietnamese
model-index:
  - name: guardspec-classifier-v5
    results: []
---

<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# guardspec-classifier (v5, candidate)

A small English + Vietnamese **prompt-injection risk classifier**, shipped as an INT8 ONNX model
(118.5 MB). It is the L2 layer of [Guard Spec](https://github.com/guard-spec/guard-spec), a
self-hosted prompt-injection guardrail gateway. It is not an LLM and does not generate text.

**v5 is a candidate, not Guard Spec's default classifier** (that is v3b). Run it in Guard Spec's shadow
mode (`SHADOW_L2_MODEL=guardspec-classifier@v5`) for at least 7 days before using it. It is trained for
tool output: benign code, configuration, logs, stack traces and long prose that v3b blocked, and attacks
hidden in such text (see Evaluation).

- Architecture: `intfloat/multilingual-e5-small` (BERT, 12 layers, hidden size 384, about 118M
  parameters) fine-tuned with an 8-label sigmoid head (multi-label).
- Labels: `benign`, `direct_injection`, `indirect_injection`, `jailbreak`, `prompt_extraction`,
  `data_exfiltration`, `tool_poisoning`, `obfuscation`.
- Risk score: **1 − sigmoid(logit_benign)**. The per-attack-label scores are advisory.
- Input: up to 256 tokens per window. Longer text is cut into windows of 254 content tokens overlapping
  by 64 and the worst window counts (Guard Spec does this; v5 was trained on exactly these windows).
  The text is passed as is (no e5 `query: ` prefix).
- Version: **v5** (2026-11-10).

## How Guard Spec uses it

| layer | what | calibration |
|---|---|---|
| L1 | rules and patterns | built in |
| **L2** | **this classifier**, risk = 1 − p(benign) | Platt scaling: `sigmoid(A · logit(risk) + B)`, A 0.8489, B −0.1176 |
| L3 | similarity to attack and benign exemplars with `multilingual-e5-small` embeddings | built in |

The calibrated layer scores are combined by a logistic regression over their logits, L1, L2, L3 weights
(0.4747, 0.9044, 0.3989), bias 0.6363 (L1 + L2 only: (0.4947, 0.9370), bias 0.4441). The gateway
**blocks at a fused score of 0.85**. `calibration.json` also sets `l2_untrusted_max` 0.88: on untrusted
content (tool results, documents) the classifier's calibrated score is capped there, so L2 alone cannot
block such content and L1 or L3 must add the rest. The cap is derived from the validation splits by
`cmd/calibrate fit`, never from the eval sets; a gateway that does not know the field ignores it, and
user messages are not capped. `thresholds.json` carries a stand-alone threshold for the classifier alone
(`risk_threshold` 0.2424, benign FPR ≤ 1% on validation); it is not the gateway's block threshold.

## Files

| file | SHA-256 | |
|---|---|---|
| `model_int8.onnx` | `1d42326716906ebc07b5dd7cb10615cb68037c8afda3ac4dbeedcff214279e31` | ONNX, INT8 dynamic quantization (QInt8 weights, per channel); 118,466,001 bytes |
| `tokenizer.json` | `6879d3648d0329c894b1cbb0c89096430e24d3c7cf5d359d4ccc87ce585c4ae4` | Hugging Face `tokenizers` file of the base model (same vocabulary and ids as v3b's) |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` | model config with `id2label` |
| `thresholds.json` | `96156d39c9a5dc1fea91c54d9db47e76281c6d31ef1b45e66a4d1310308659d2` | risk definition, thresholds, validation metrics |
| `calibration.json` | `78d02581cb4042f954bb3f5b95b826d7bf66ca5333d35915eb53d10984edbdb5` | Guard Spec fusion calibration and the untrusted-content cap |

ONNX inputs: `input_ids` and `attention_mask` (int64, `[batch, seq]`). Output: `logits` (float32,
`[batch, 8]`) in the label order of `config.json`. The usage example of the v3b card applies unchanged.

## Training data

Fine-tuned from `intfloat/multilingual-e5-small` (MIT, revision
`614241f622f53c4eeff9890bdc4f31cfecc418b3`) with the v3b recipe, one training example per gateway
window (50,190 rows and 51,789 windows per epoch; 12,775 validation rows). The v4 data (the v3b data:
deepset/prompt-injections, Apache-2.0; Lakera/gandalf_ignore_instructions, MIT;
jackhhao/jailbreak-classification, Apache-2.0; OpenAssistant/oasst2, Apache-2.0; nvidia/HelpSteer2,
**CC-BY-4.0**, prompts only; Guard Spec project-written rows, Apache-2.0; the v4 Vietnamese rows of
`train/data/gen_vi_v4.py`; owner-supplied synthetic EN/VI rows and AI-written OTP/eKYC rows, used with
consent and **not redistributed**), plus the v5 set (`train/data/build_v5.py`, 15,876 rows):

- benign windows of code, configuration, Dockerfiles, CI files, shell scripts, SQL and diffs from pinned
  tags of permissively licensed repositories (Kubernetes, CPython, Rust, Node.js, cosign, Ory Hydra,
  oauth2-proxy, Ollama, openai-python, detect-secrets, PostgreSQL regression tests, requests, ripgrep);
  U.S. Code titles and Vietnamese laws and pre-1900 works from vi.wikisource; generated logs, stack
  traces, JSON, CSV, terminal output and Vietnamese-commented code;
- attack rows of the public training set embedded in such hosts at 12 positions, half of them with a
  minimal-pair twin (the same host without the payload).

**Attribution.** HelpSteer2: NVIDIA, *HelpSteer2: Open-source dataset for training top-performing
reward models* (Wang et al., 2024), CC-BY-4.0, https://huggingface.co/datasets/nvidia/HelpSteer2. Credit
also goes to deepset, Lakera, jackhhao and the upstream authors, the OpenAssistant contributors, and the
authors of the repositories and texts above (`train/DATA_LICENSES.md`, v5). Vietnamese project rows are
machine-written and were not reviewed by a native speaker. Details: `train/DATA_CARD.md` ("v5 data"),
`train/DATA_LICENSES.md` and `train/MODEL_CARD.md` ("v5") in the Guard Spec repository.

## Evaluation

Gateway scores, fused L1 + L2 + L3, blocking at 0.85, on the hold-out halves of Guard Spec's eval sets
(held out from training, selection and calibration, scored once) and on the owner's hold-out rows
(owner-written, not redistributed). v3b with its shipped calibration, v5 with `calibration.json` and
the cap.

| | v3b (default) | **v5** |
|---|---|---|
| `eval/data` (user messages, 1,113 rows): TPR at FPR ≤ 1% / TPR and FPR at 0.85 | 0.942 / 0.9435 and 1.57% | 0.940 / 0.9435 and 1.17% |
| `eval/codelog` (benign tool output, 162 rows): FPR, code corroboration off / on | 20.99% / 7.41% | 0.62% / 0.62% |
| `eval/embedded` (attacks in code and logs), corroboration off: TPR / FPR | 0.779 / 15.1% | 0.861 / 4.7% |
| `eval/embedded`, corroboration on: TPR / FPR | 0.719 / 5.7% | 0.824 / 2.5% |
| `eval/embedded`: TPR at FPR ≤ 1% | 0.374 | 0.748 |
| owner hold-outs (408 attacks / 272 benign): TPR / FPR at 0.85 | 0.762 / 1.5% | 0.848 / 2.9% |
| owner hold-outs: TPR at FPR ≤ 1% | 0.503 | 0.797 |
| `val_v5_holdout` (1,721 benign code and log windows / 493 embedded attacks, tool path, corroboration off): FPR / TPR at 0.85 / TPR at FPR ≤ 1% | 0.9% / 0.665 / 0.665 | 0.0% / 0.623 / 0.988 |
| `val_v3_holdout` (1,173 benign / 337 generated attacks): FPR / TPR at 0.85 | 0.5% / 0.953 | 0.5% / 0.887 |
| `val_v4_holdout` (131 benign / 10 attacks): FPR / TPR at 0.85 | 3.8% / 0.800 | 0.8% / 0.900 |
| the 4 reported benign Vietnamese sentences blocked | 4 | 0 |

## Limitations

- On documents of 100k to 200k tokens the false-positive goal is not met yet; a third round of data
  (benign prose embedded in code and log hosts) is needed.
- On the owner hold-outs it blocks 8 of 272 benign rows (v3b 4), and on `val_v3_holdout` it catches
  0.887 of the generated attacks at the block threshold (v3b 0.953).
- The cap keeps an embedded attack that only the classifier recognises below the block threshold on the
  tool path: on `val_v5_holdout` it catches 0.623 at 0.85 (v3b 0.665) while ranking them far better.
- Without the cap (a gateway that ignores `l2_untrusted_max`) it blocks more benign tool output than
  with it: `eval/codelog` dev FPR 6.8% instead of 2.0%.
- Synthetic data, 256-token windows, and no content moderation, as for v3b.
