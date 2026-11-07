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
  - name: guardspec-classifier-v4
    results: []
---

<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# guardspec-classifier (v4, candidate)

A small English + Vietnamese **prompt-injection risk classifier**, shipped as an INT8 ONNX model
(118.5 MB). It is the L2 layer of [Guard Spec](https://github.com/guard-spec/guard-spec), a
self-hosted prompt-injection guardrail gateway. It is not an LLM and does not generate text.

**v4 is a candidate, not Guard Spec's default classifier** (that is v3b). Compare it with v3b in
Guard Spec's shadow mode (`SHADOW_L2_MODEL=guardspec-classifier@v4`) before using it. It blocks fewer
benign Vietnamese messages (teencode, ordinary instructions such as "bỏ qua bước này nếu bạn đã cài
rồi") but catches somewhat fewer attacks than v3b at the gateway's block threshold (see Evaluation).

- Architecture: `intfloat/multilingual-e5-small` (BERT, 12 layers, hidden size 384, about 118M
  parameters) fine-tuned with an 8-label sigmoid head (multi-label).
- Labels: `benign`, `direct_injection`, `indirect_injection`, `jailbreak`, `prompt_extraction`,
  `data_exfiltration`, `tool_poisoning`, `obfuscation`.
- Risk score: **1 − sigmoid(logit_benign)**. The per-attack-label scores are advisory.
- Input: up to 256 tokens per window; longer text should be split into windows, taking the maximum
  risk (Guard Spec does this). The text is passed as is (no e5 `query: ` prefix).
- Version: **v4** (2026-11-07).

## How Guard Spec uses it

| layer | what | calibration |
|---|---|---|
| L1 | rules and patterns | built in |
| **L2** | **this classifier**, risk = 1 − p(benign) | Platt scaling: `sigmoid(A · logit(risk) + B)`, A 0.8444, B −0.6348 |
| L3 | similarity to attack and benign exemplars with `multilingual-e5-small` embeddings | built in |

The calibrated layer scores are combined by a logistic regression over their logits, L1, L2, L3 weights
(0.5746, 0.8915, 0.5591), bias 0.6783 (L1 + L2 only: (0.6185, 0.9375), bias 0.4156). The gateway
**blocks at a fused score of 0.85**. These values are in `calibration.json`, which Guard Spec loads from
the model directory; they are identical to the calibration built into the gateway.
`thresholds.json` carries a stand-alone threshold for the classifier alone (`risk_threshold` 0.9251,
benign FPR ≤ 1% on validation); it is not the gateway's block threshold.

## Files

| file | SHA-256 | |
|---|---|---|
| `model_int8.onnx` | `70feb1810bb97a78b513e32890088b1d4df6507a0eb2f09103fbf24f49095aef` | ONNX, INT8 dynamic quantization (QInt8 weights, per channel); 118,466,001 bytes |
| `tokenizer.json` | `2b95ee17661f8dfbbceaba374f6d277a6b5d8e1898c070a16331622024f58c67` | Hugging Face `tokenizers` file of the base model |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` | model config with `id2label` |
| `thresholds.json` | `5b9d22f8bcff8892856b366d529824c2f9897867fec3c2fdf032f043bc642a54` | risk definition, thresholds, validation metrics |
| `calibration.json` | `0f21e68e6b0b7a109597c55ea0ca8020751f5d3e67085e10eb1ef7bef79b952c` | Guard Spec fusion calibration |

ONNX inputs: `input_ids` and `attention_mask` (int64, `[batch, seq]`). Output: `logits` (float32,
`[batch, 8]`) in the label order of `config.json`. The usage example of the v3b card applies unchanged.

## Training data

Fine-tuned from `intfloat/multilingual-e5-small` (MIT, revision
`614241f622f53c4eeff9890bdc4f31cfecc418b3`) with the v3b recipe. About 34,350 training rows per epoch
and 8,342 validation rows, EN and VI: the v3b data (deepset/prompt-injections, Apache-2.0;
Lakera/gandalf_ignore_instructions, MIT; jackhhao/jailbreak-classification, Apache-2.0;
OpenAssistant/oasst2, Apache-2.0; nvidia/HelpSteer2, **CC-BY-4.0**, prompts only; Guard Spec
project-written rows, Apache-2.0), plus:

- new Guard Spec Vietnamese rows (Apache-2.0, `train/data/gen_vi_v4.py`): hard negatives such as
  "bỏ qua bước …", "kệ", "giờ bạn là <role>" followed by an ordinary task, banking-support questions,
  native teencode chat, and minimal-pair attacks;
- owner-supplied synthetic EN/VI rows, batch 1 and 2 (prompt injection, Vietnamese teencode /
  no-diacritics, banking OTP/KYC), used with the owner's consent and **not redistributed**: 1,140
  training-pool rows and a 460-row hold-out;
- AI-written OTP/eKYC rows made for the project (**not redistributed**), as in v3b.

**Attribution.** HelpSteer2: NVIDIA, *HelpSteer2: Open-source dataset for training top-performing
reward models* (Wang et al., 2024), CC-BY-4.0, https://huggingface.co/datasets/nvidia/HelpSteer2. Credit
also goes to deepset, Lakera, jackhhao and the upstream authors, and the OpenAssistant contributors.
Vietnamese project rows are machine-written and were not reviewed by a native speaker. Details:
`train/DATA_CARD.md`, `train/DATA_LICENSES.md` and `train/MODEL_CARD.md` ("v4") in the Guard Spec repository.

## Evaluation

Guard Spec's eval set (2,176 rows; EN 926, VI 1,250), held out from training, selection and calibration
and measured once. Gateway scores, fused L1 + L2 + L3, blocking at 0.85:

| | ROC AUC | TPR at 0.85 | FPR at 0.85 | EN FPR | VI FPR | VI teencode FPR | VI no-diacritics FPR |
|---|---|---|---|---|---|---|---|
| v3b (default) | 0.9865 | 0.939 | 1.4% | 1.7% | 1.25% | 3.5% | 0.4% |
| **v4** | 0.9853 | 0.932 | 1.2% | 1.1% | 1.25% | 1.4% | 1.7% |

On the owner's held-out rows (184 benign / 276 attacks), v4 blocks 1 benign row (v3b 3) and catches 0.688
of the attacks (v3b 0.714); on owner Vietnamese teencode / no-diacritics rows its ROC AUC is 0.878 (v3b
0.763). It passes three of the four Vietnamese sentences that v3b blocked.

## Limitations

- Lower recall than v3b at the block threshold on several groups (eval: Vietnamese data exfiltration
  0.820 vs 0.918, tool poisoning 0.919 vs 0.973, English leet 0.775 vs 0.825).
- Vietnamese text without diacritics: 1.7% benign FPR on eval (v3b 0.4%).
- Informal Vietnamese remains the weak spot: owner teencode attacks are caught at 0.47 at the block
  threshold.
- Synthetic data, 256-token windows, and no content moderation, as for v3b.
