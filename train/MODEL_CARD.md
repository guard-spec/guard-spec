---
license: apache-2.0
language: [en, vi]
base_model: intfloat/multilingual-e5-small
pipeline_tag: text-classification
tags: [prompt-injection, jailbreak, guardrail, onnx, int8]
---

# guardspec-classifier-v0

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

guardspec-classifier-v0 is a small multilingual (English + Vietnamese)
**attack-risk classifier** for the Guard Spec prompt-injection gateway. It is
not an LLM. It is `intfloat/multilingual-e5-small` (118M parameters, 12
layers, hidden size 384) fine-tuned with an 8-way sigmoid head. It ships as an
INT8 ONNX model, 118.5 MB.

## Intended use

- Scoring user prompts, retrieved documents, tool outputs and tool
  definitions before an LLM sees them.
- Use it as one signal next to the gateway's other detectors, not as the only
  control.
- Inputs longer than 256 tokens should be split into windows, taking the
  maximum risk. The gateway runner and `evaluate.py` both do this.

Out of scope:

- Content moderation: toxicity, harmful requests.
- Languages other than English and Vietnamese.
- Any use where a false positive or a false negative has no human or policy
  backstop.

## Outputs

`logits[8]`, with a sigmoid applied per label. The labels are `benign`,
`direct_injection`, `indirect_injection`, `jailbreak`, `prompt_extraction`,
`data_exfiltration`, `tool_poisoning` and `obfuscation`. Definitions are in
`LABELING.md`.

**Overall risk = 1 − p(benign).** Calibration compared this with the maximum
over the attack labels and picked 1 − p(benign): it had the higher validation
TPR at benign FPR ≤ 1% (0.993 vs 0.992), and the two scores are close.

Thresholds are in `thresholds.json`, calibrated on the validation split with
the INT8 model:

| threshold | value | meaning |
|---|---|---|
| `risk_threshold` | 0.7298 | benign FPR ≤ 1% on validation |
| `risk_threshold_review` | 0.0145 | benign FPR ≤ 5% on validation, for review or logging |
| per-label | direct 0.739 · indirect 0.363 · jailbreak 0.221 · extraction 0.504 · exfiltration 0.462 · tool poisoning 0.737 · obfuscation 0.268 | max F1 on validation, advisory |

## Training

| | |
|---|---|
| base model | `intfloat/multilingual-e5-small`, MIT (model card), revision `614241f622f53c4eeff9890bdc4f31cfecc418b3` |
| data | 15,850 training rows, 2,228 validation rows (`DATA_CARD.md`) |
| recipe | AdamW, lr 5e-5, weight decay 0.01, 6% warmup with linear decay, batch 32, max_len 256, BCE loss, seed 20261105 |
| early stopping | on validation TPR at FPR ≤ 1%, patience 1 |
| run | 5 epochs; the best was the last (epoch 5) |
| time | 20.1 min on an Apple M3 Max (PyTorch 2.5.1, MPS) |
| versions | all pinned in `pyproject.toml` and `uv.lock` |

Reproduce:

```sh
cd train
uv sync
uv run python data/build_data.py   # deterministic, about 17 MB download
uv run python train.py             # writes runs/guardspec-classifier-v0/best
uv run python export.py            # ONNX FP32 -> INT8, parity, calibration, writes ../models/local/...
uv run python evaluate.py          # eval set report + ProtectAI comparison + latency
```

## INT8 vs FP32

Measured on the validation split (`reports/export_report.json`):

| check | result |
|---|---|
| PyTorch vs ONNX FP32 | max \|Δp\| 7e-7 |
| INT8 vs FP32, all probabilities | max \|Δp\| 0.76, mean 0.003 |
| INT8 vs FP32, risk score | p99 \|Δ\| 0.058; 16 of 2,228 rows differ by more than 0.1 |
| ΔAUC (INT8 − FP32) | +0.0001 |
| same decision at the threshold | 99.7% of rows |

Quantization is onnxruntime dynamic quantization: QInt8 weights, per-channel.

## Evaluation: eval set (EN 926 rows, VI 1,250 rows)

`evaluate.py` scores `eval/` once, for the final report. Training and
calibration never used it.

The comparison model is `protectai/deberta-v3-base-prompt-injection-v2`
(Apache-2.0, revision `90c9989b1a34`). The requested *small* v2 model is
gated on Hugging Face, and no token was available, so the comparison uses
the base model (184M parameters) from the same family, run through
transformers with max_len 512.

How to read the columns:

- **TPR@FPR≤1%** uses the threshold read off each group's own ROC curve.
- **@ thr** is the deployed threshold: our validation-calibrated 0.7298, and
  ProtectAI's default 0.5.

| group | ours AUC | ours TPR@FPR≤1% | ours TPR / FPR @ thr | ProtectAI AUC | ProtectAI TPR@FPR≤1% | ProtectAI TPR / FPR @ 0.5 |
|---|---|---|---|---|---|---|
| all | **0.976** | **0.485** | 0.957 / 0.074 | 0.784 | 0.262 | 0.886 / 0.506 |
| en | **0.978** | **0.486** | 0.957 / 0.069 | 0.897 | 0.351 | 0.868 / 0.234 |
| vi | **0.973** | **0.396** | 0.957 / 0.076 | 0.661 | 0.059 | 0.901 / 0.661 |
| vi orig | 0.994 | 0.827 | 0.976 / 0.042 | 0.642 | 0.062 | 0.861 / 0.631 |
| vi no_diacritics | 0.966 | 0.385 | 0.943 / 0.076 | 0.653 | 0.075 | 0.937 / 0.686 |
| vi teencode | 0.961 | 0.239 | 0.938 / 0.105 | 0.692 | 0.062 | 0.894 / 0.671 |

Per-category AUC, with all benign rows of the language as negatives:

| | direct | indirect | jailbreak | extraction | exfiltration | tool poisoning | obfuscation |
|---|---|---|---|---|---|---|---|
| ours, EN | 0.978 | 0.973 | 0.947 | 0.993 | 0.970 | 0.977 | 0.978 |
| ours, VI | 0.984 | 0.977 | 0.967 | 0.981 | 0.967 | 0.951 | 0.960 |
| ProtectAI, EN | 0.913 | 0.826 | 0.877 | 0.984 | 0.743 | 0.814 | 0.819 |
| ProtectAI, VI | 0.626 | 0.692 | 0.657 | 0.669 | 0.638 | 0.634 | 0.774 |

**Benign FPR at the calibrated threshold is 6.9% (EN) and 7.6% (VI), not the
1% calibrated on validation.** The eval set's hard negatives are harder than
our validation benign rows; see Limitations. All groups, variants and the
category-head hit rates are in `reports/eval_report.{md,json}`.

## Latency

INT8 ONNX with onnxruntime 1.20.1 on CPU (Apple M3 Max), batch 1, model only
(tokenization excluded):

| threads | 128 tokens p50 / p99 | 256 tokens p50 / p99 |
|---|---|---|
| default (14 cores) | 17.5 / 30.2 ms | 33.4 / 59.2 ms |
| 1 | 55.3 / 71.0 ms | 103.4 / 114.5 ms |

## Limitations

- **Machine-written Vietnamese.** The Vietnamese training data is synthetic,
  machine-written and agent-labelled, with no native-speaker review. Teencode
  comes from rules.
- **False positives on idioms and some VI variants.** At the calibrated
  threshold, 74 of the 1,005 eval benign rows are flagged. The
  highest-scoring ones are:
  - everyday English idioms: "Just ignore my previous email", "Forget about
    it", "Please ignore the typos";
  - Vietnamese benign rows written without diacritics or in teencode,
    including documents with only partly stripped diacritics and plain
    requests such as "viet doan van ngan ta canh mua thu ha noi".

  The model has partly learned "no diacritics / teencode / carrier format →
  attack". The next data iteration should add more benign idioms and more
  benign variant text, including partly transformed carriers. These failure
  types were read off the eval set after training; v0 was not changed in
  response, to keep the eval clean.
- **Optimistic validation.** Validation shares templates with training. Its
  1%-FPR threshold does not transfer to new distributions, so recalibrate on
  in-domain traffic before blocking.
- **Template artefacts.** Most attacks are template-generated. Real attackers
  are more varied: long multi-turn jailbreaks, new encodings, other
  languages.
- **Per-label heads are advisory.** On the eval set, for example, `prompt_extraction`
  is the top-1 label for only 23% of EN extraction rows, which are mostly
  Gandalf rows that also carry an override. Use the overall risk for decisions.
- **Truncation.** Inputs are truncated at 256 tokens per window. A payload in
  a very long document is only seen if the caller windows the input.
- **Payload types.** Attacks are instruction-manipulation patterns. The model
  says nothing about whether a request is harmful in itself.

## License and attribution

- **Model weights and project data**: Apache-2.0, copyright The Guard Spec
  Authors.
- **Base model**: `intfloat/multilingual-e5-small` (MIT).
- **Source datasets**: deepset/prompt-injections (Apache-2.0),
  Lakera/gandalf_ignore_instructions (MIT),
  jackhhao/jailbreak-classification (Apache-2.0), OpenAssistant/oasst2
  (Apache-2.0). See `DATA_LICENSES.md`.
