---
license: apache-2.0
language: [en, vi]
base_model: intfloat/multilingual-e5-small
pipeline_tag: text-classification
tags: [prompt-injection, jailbreak, guardrail, onnx, int8]
---

# guardspec-classifier-v3

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

## v3 (2026-11-04)

v3 has the same architecture, labels, export and runtime as v1/v2 (below):
`intfloat/multilingual-e5-small` at the pinned MIT revision, 8-label sigmoid head, risk
1 − p(benign), INT8 ONNX, 118.5 MB, same latency. It targets v2's English false positives and
its Vietnamese no-diacritics regression on `val_hard`, and adds realistic attacks. The data changes
are in `DATA_CARD.md` ("v3 changes"): English hard negatives and minimal pairs (`data/gen_v3.py`),
HelpSteer2 prompts (CC-BY-4.0), realistic EN/VI rows (`data/realistic/`), a per-language
benign:attack ratio (EN 2.0, VI 1.75) and formal Vietnamese with diacritics seen twice per epoch.
Recipe unchanged (AdamW 5e-5, 5 epochs, batch 32, BCE, v2 augmentation).

**The eval-set results are pending measurement by the coordinator** (measured once, after this
work). Everything below uses training and validation data only, plus two hold-outs.

| | v3 |
|---|---|
| data | 30,133 train (31,081 rows per epoch with the oversampling); selection/calibration on `val` 4,749 + `val_hard` 829 + `val_vi_variants` 1,408 + `val_v3` 508 = 7,494 rows |
| hold-outs (never used for selection or calibration) | `val_v3_holdout` 1,510 rows (template set C, written before the training templates); `val_realistic_holdout` 613 rows (disjoint organisations and scenarios) |
| run | 5 epochs, best epoch 5 by validation loss (0.0813, 0.0426, 0.0296, 0.0296, 0.0247); 42.0 min on Apple M3 Max, MPS |
| `risk_threshold` | 0.0301 (benign FPR ≤ 1% on the four validation splits combined, INT8; v3 is far more confident on benign rows than v2, whose threshold was 0.9237) |
| INT8 vs FP32 | ΔAUC −0.0003; p99 \|Δrisk\| 0.11; same decision at the threshold on 99.4% of rows; PyTorch vs ONNX FP32 max \|Δp\| 7e-7 |
| latency (onnxbench, INT8, M3 Max, 1 stream) | 64 tokens p50 4.0 ms; 256 tokens p50 14.4 ms; 512 tokens p50 35.6 ms (same model size as v2) |

SHA-256 of `models/local/guardspec-classifier-v3/`:

```
8f4fa2550651a510fef6b7aefb80b9a4132597f208a3598a2b8ab7cfe27194a2  model_int8.onnx
2b95ee17661f8dfbbceaba374f6d277a6b5d8e1898c070a16331622024f58c67  tokenizer.json
c89d10db99567d790a4a33d551eef09dcd0b0786877d22a67033c09c34cf9f72  config.json
c3b33b7cf18f9523f1784078276c21aadc16e7f8d9fd9002596f1923769a6fdd  thresholds.json
```

Fusion calibration for v3 (`go run -tags onnx ./cmd/calibrate fit`, on the four validation splits,
built in as `ml.BuiltinCalibrations`): Platt A 0.9853, B 0.3199; logreg(L1,L2,L3) W (0.6047, 0.9279,
0.2477), B 0.5491. Out-of-fold (5-fold) on the same 7,494 rows: AUC 0.996, TPR@FPR≤1% 0.981, and at
the gateway's 0.85 block threshold **TPR 0.965 at benign FPR 0.24%**. v2 on the same rows (its
calibration refitted the same way): TPR 0.888 at FPR 0.48%.

### Validation, fused L1+L2+L3 at 0.85, out-of-fold, per group

Benign FPR (false positives / benign rows) and TPR; L1 and L3 are the same for both models.

| group | benign / attack | v2 FPR | v3 FPR | v2 TPR | v3 TPR |
|---|---|---|---|---|---|
| all | 5,840 / 1,654 | 0.55% (32) | **0.24% (14)** | 0.872 | **0.965** |
| EN | 2,124 / 684 | 0.85% (18) | **0.33% (7)** | 0.895 | **0.963** |
| VI orig | 1,105 / 315 | 0.27% (3) | **0.00% (0)** | 0.937 | **0.990** |
| VI no-diacritics | 1,038 / 272 | 0.48% (5) | 0.48% (5) | 0.919 | **0.974** |
| VI teencode | 1,437 / 323 | 0.42% (6) | **0.14% (2)** | 0.777 | **0.938** |
| `val` EN | 1,489 / 650 | 1.14% (17) | **0.47% (7)** | 0.894 | 0.971 |
| `val_hard` VI no-diacritics | 129 / 8 | 0.78% (1) | 1.55% (2) | 0.750 | 0.750 |
| `val_vi_variants` teencode | 681 / 47 | 0.44% (3) | 0.15% (1) | 0.468 | 0.723 |
| `val_v3` | 477 / 31 | 0.21% (1) | 0.00% (0) | 1.000 | 0.871 |

The `val_hard` Vietnamese no-diacritics regression of v2 is fixed in the classifier itself: at v2's
threshold (0.9237) v2 blocked 8.5% of those 129 benign rows and v3 blocks 0.8%; at v3's own
threshold, 3.1% (`reports/variant_report_v3.json`). Fused, the two models differ by one row there.
These splits chose the epoch, the threshold and the fusion weights, so they flatter both models.

### Hold-outs, scored once at the end

Fused L1+L2+L3 at 0.85 with each model's calibration fixed beforehand on validation (v2: its
built-in calibration). "v3 without realistic" is the same recipe trained with
`GUARD_V3_REALISTIC=0` (and its own validation calibration).

| hold-out / group | benign / attack | v2 FPR / TPR | v3 without realistic FPR / TPR | **v3** FPR / TPR |
|---|---|---|---|---|
| `val_v3_holdout` all | 1,173 / 337 | 3.1% / 0.964 | 1.8% / 0.988 | **0.4% / 0.979** |
| EN | 544 / 128 | 4.6% / 0.961 | 1.7% / 0.992 | **0.9% / 0.977** |
| VI orig | 210 / 70 | 2.9% / 1.000 | 1.0% / 1.000 | **0.0% / 1.000** |
| VI no-diacritics | 210 / 70 | 1.4% / 0.971 | 3.3% / 1.000 | **0.0% / 0.971** |
| VI teencode | 209 / 69 | 1.0% / 0.928 | 1.4% / 0.957 | **0.0% / 0.971** |
| `val_realistic_holdout` all | 366 / 247 | 6.8% / 0.810 | 4.1% / 0.814 | **1.4% / 0.895** |
| EN | 162 / 120 | 6.2% / 0.750 | 3.1% / 0.725 | **1.2% / 0.825** |
| VI orig (formal, diacritics) | 169 / 102 | 7.7% / 0.892 | 4.1% / 0.922 | **1.2% / 0.971** |
| VI no-diacritics | 26 / 21 | 7.7% / 0.714 | 11.5% / 0.810 | 3.8% (1 row) / 0.905 |
| VI teencode | 9 / 4 | 0.0% / 1.000 | 0.0% / 0.750 | 0.0% / 1.000 |

AUC (fused): `val_v3_holdout` v2 0.995, v3 0.998; `val_realistic_holdout` v2 0.955, without
realistic 0.961, v3 0.985. Caveats: both hold-outs are machine-written (set C by the same author
as the training templates, the realistic hold-out by the same model family as the realistic
training rows), so they are optimistic about real traffic; small groups (realistic VI
no-diacritics and teencode) cannot be read row for row.

### What was tried

Five training runs of 30–42 minutes each (the v3 data is about 30% larger than v2's) and one weight average:

| run | data | change | validation: benign FPR at TPR 0.95 (L2 alone, all four splits) | result |
|---|---|---|---|---|
| r1 | without realistic | v2 recipe, seed 20261105 | 0.72% (v2: 1.46%) | big EN gain, VI teencode FPs on `val_vi_variants` |
| r2 | without realistic | seed 20261106 | 0.70% | similar to r1: the data, not the seed |
| soup(r1, r2) | without realistic | uniform weight average (`soup.py`) | 0.91% | worse than either run; dropped |
| r3 | **with realistic** | formal VI with diacritics ×2 per epoch | **0.14%** | **chosen as v3** |
| r4 | with realistic | no upweighting | 0.25% | slightly worse than r3 on every summary |
| no-realistic re-run | without realistic | r1 recipe, retrained only to score the hold-outs (r1/r2 checkpoints had been deleted) | 0.72% | as r1 |

The realistic data helps even on validation rows that are not from it (FPR at TPR 0.95 0.14% vs
0.46–0.49%). Label smoothing, a learning-rate sweep and `multilingual-e5-base` were not tried: the
small model met every validation and hold-out target, so the base model's 2–3× latency was not
needed.

Reproduce v3:

```sh
cd train
uv sync
uv run python data/build_data.py   # deterministic; GUARD_V3_REALISTIC=0 for the "without" arm
uv run python train.py             # writes runs/guardspec-classifier-v3/best
uv run python export.py            # writes ../models/local/guardspec-classifier-v3
uv run python variant_report.py --model ../models/local/guardspec-classifier-v3
cd .. && go run -tags onnx ./cmd/calibrate fit   # cgo flags: see the Makefile
```

The sections below describe v2 and v1.

## v2 (2026-11-04)

v2 has the same architecture, recipe and export as v1 (below). It targets
v1's false positives on Vietnamese benign text in teencode and without
diacritics. The data changes are in `DATA_CARD.md` ("v2 changes"):
`data/gen_vi_v2.py` (everyday benign Vietnamese with admin vocabulary,
minimal pairs), randomized teencode (`common.teencode_v2`), the same
benign:attack ratio (1.5) in every variant, and training-time
no-diacritics / teencode augmentation (0.15 / 0.15, label-independent).

| | v2 |
|---|---|
| data | 23,404 train; validation `val` 3,648 + `val_hard` 829 + `val_vi_variants` 1,408 |
| run | 5 epochs, best epoch 5 by validation loss (0.1184, 0.0544, 0.0354, 0.0354, 0.0319); 24.4 min on Apple M3 Max, MPS |
| `risk_threshold` | 0.9237 (benign FPR ≤ 1% on the three validation splits combined, INT8) |
| INT8 vs FP32 | ΔAUC +0.0005; p99 \|Δrisk\| 0.16; same decision at the threshold on 99.4% of rows |

SHA-256 of `models/local/guardspec-classifier-v2/`:

```
56e431f224eb113c95ebaf4656d19b73abe10cfc0c4dafd50633a00ccce3dcb6  model_int8.onnx
2b95ee17661f8dfbbceaba374f6d277a6b5d8e1898c070a16331622024f58c67  tokenizer.json
c89d10db99567d790a4a33d551eef09dcd0b0786877d22a67033c09c34cf9f72  config.json
94784a15f78337466e6ee16f23cfabd6cb80f1f80d14c354e79fd0181d86a2e3  thresholds.json
```

Validation, classifier alone, benign FPR at each model's own threshold
(v1 0.8768, v2 0.9237), `uv run python variant_report.py` (full tables:
`reports/variant_report_v{1,2}.json`):

| split / group | benign rows | v1 FPR | v2 FPR | v1 TPR | v2 TPR |
|---|---|---|---|---|---|
| `val` EN | 830 | 0.8% | 0.6% | 0.980 | 0.967 |
| `val` VI orig / no-diacritics / teencode | 446 / 447 / 480 | 4.5% / 11.4% / 16.7% | 0.0% / 0.4% / 0.4% | 0.996 / 0.988 / 0.988 | 0.996 / 0.992 / 0.984 |
| `val_hard` EN | 346 | 4.0% | 3.5% | 0.727 | 0.818 |
| `val_hard` VI orig / no-diacritics / teencode | 129 / 129 / 154 | 0.0% / 2.3% / 1.3% | 2.3% / **8.5%** / 3.2% | 0.75 / 0.75 / 0.67 | 1.00 / 1.00 / 0.67 |
| `val_vi_variants` orig / no-diacritics / teencode | 328 / 328 / 681 | 13.1% / 23.5% / 27.2% | 0.0% / 0.0% / 0.7% | 0.75 / 0.75 / 0.64 | 0.83 / 0.67 / 0.60 |

`val` and `val_vi_variants` were also used to choose the epoch and the
threshold, so they flatter v2. `val_hard` Vietnamese without diacritics got
worse (3 → 11 of 129 rows): v2 trades some false positives on v1's
hard-negative templates for far fewer on everyday admin vocabulary.

Fusion calibration for v2 (`go run -tags onnx ./cmd/calibrate fit`, on the
same three splits, built in as `ml.BuiltinCalibrations`): Platt A 0.9364,
B −0.5280; out-of-fold logreg(L1,L2,L3) AUC 0.995, TPR@0.85 0.926 at benign
FPR 0.5%.

**Eval set results, fused L1+L2+L3 at the gateway's 0.85 block threshold**
(`eval/`, 2,176 rows, measured once on 2026-11-04; v1 measured with the same
L1 for comparison; `eval/baseline-onnx.json` now holds the v2 run):

| | AUC | TPR@FPR≤1% | TPR | FPR | EN FPR | VI FPR | VI teencode FPR | VI no-diacritics FPR |
|---|---|---|---|---|---|---|---|---|
| v1 | 0.985 | 0.915 | 0.939 | 2.7% | 1.1% | 3.6% | 7.0% | 3.8% |
| v2 | 0.985 | 0.922 | 0.933 | 2.0% | 2.2% | 1.9% | 1.4% | 3.0% |
| v2, cascade | 0.987 | 0.936 | 0.945 | 2.1% | 2.5% | 1.9% | 1.4% | 3.0% |

v2 meets the teencode target (≤ 2%) and keeps TPR within 1 point of v1, but
misses the overall (≤ 1.5%) and no-diacritics (≤ 2%) targets, and English
benign FPR doubled (4 → 8 of 364 rows). It replaces v1 because it blocks
fewer benign rows overall (20 vs 27 of 1,005) and catches more at equal FPR.

Reproduce v2:

```sh
cd train
uv sync
uv run python data/build_data.py   # deterministic; writes val_vi_variants.jsonl too
uv run python train.py             # writes runs/guardspec-classifier-v2/best
uv run python export.py            # writes ../models/local/guardspec-classifier-v2
uv run python variant_report.py --model ../models/local/guardspec-classifier-v2
cd .. && go run -tags onnx ./cmd/calibrate fit   # cgo flags: see the Makefile
```

The sections below describe v1.

# guardspec-classifier-v1

guardspec-classifier-v1 is a small multilingual (English + Vietnamese)
**attack-risk classifier** for the Guard Spec prompt-injection gateway. It is
not an LLM. It is `intfloat/multilingual-e5-small` (118M parameters, 12
layers, hidden size 384) fine-tuned with an 8-way sigmoid head, and it ships
as an INT8 ONNX model of 118.5 MB.

v1 replaces v0. Both packages stay in `models/local/`, and v0's reports are
kept as `reports/*_v0.*`. **The change in v1 is fewer false positives on
benign text**: on the eval set, English benign FPR at the calibrated threshold
falls from 6.9% to 1.4%, and Vietnamese from 7.6% to 4.7%.

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
TPR at benign FPR ≤ 1% (0.979 vs 0.935).

Thresholds are in `thresholds.json`, calibrated with the INT8 model on `val`
and `val_hard` combined:

| threshold | value | meaning |
|---|---|---|
| `risk_threshold` | 0.8768 | benign FPR ≤ 1% on combined validation |
| `risk_threshold_review` | 0.0234 | benign FPR ≤ 5% on combined validation, for review or logging |
| per-label | direct 0.821 · indirect 0.686 · jailbreak 0.357 · extraction 0.670 · exfiltration 0.624 · tool poisoning 0.439 · obfuscation 0.237 | max F1 on validation, advisory |

At `risk_threshold`, the two validation files behave differently:

| split | benign FPR | TPR |
|---|---|---|
| `val` | 0.2% | 98.8% |
| `val_hard` (unseen templates) | 2.4% | 69% (of only 36 attacks) |

## Training

| | |
|---|---|
| base model | `intfloat/multilingual-e5-small`, MIT (model card), revision `614241f622f53c4eeff9890bdc4f31cfecc418b3` |
| data | 17,833 train, 2,511 `val`, 747 `val_hard` (`DATA_CARD.md`). New in v1: hard negatives, minimal pairs, balanced variant rates |
| recipe | as v0: AdamW, lr 5e-5, weight decay 0.01, 6% warmup with linear decay, batch 32, max_len 256, BCE loss, seed 20261105 |
| epoch selection | v1 changes the selection metric to **validation loss**. The first v1 run selected on TPR@1%FPR as v0 did; that metric swung between 0.70 and 0.96 across epochs, because it depends on a handful of validation rows, and it stopped at an undertrained epoch 1. |
| run | 5 epochs; the best was epoch 5 |
| time | 21.2 min on an Apple M3 Max (PyTorch 2.5.1, MPS). MPS training is not bit-reproducible: epoch-1 metrics differed between the two v1 runs. |

Reproduce:

```sh
cd train
uv sync
uv run python data/build_data.py   # deterministic, about 17 MB download
uv run python train.py             # writes runs/guardspec-classifier-v1/best
uv run python export.py            # ONNX FP32 -> INT8, parity, calibration, writes ../models/local/...-v1
uv run python evaluate.py --skip-compare
```

## INT8 vs FP32

Measured on validation, combined (`reports/export_report_v1.json`):

| check | result |
|---|---|
| PyTorch vs ONNX FP32 | max \|Δp\| 8e-7 |
| INT8 vs FP32, risk score | ΔAUC +0.0014; p99 \|Δrisk\| 0.13; 41 of 3,258 rows differ by more than 0.1 |
| same decision at the threshold | 99.5% of rows |

Quantization is onnxruntime dynamic quantization: QInt8 weights, per-channel.

## Evaluation: eval set (EN 926 rows, VI 1,250 rows)

`evaluate.py` scores `eval/` once, for the final report, using aggregate
metrics only. Training, calibration and model selection never used it, and
the v1 generators were written without reading eval rows.

How to read the columns:

- **TPR@FPR≤1%** uses the threshold read off each group's own ROC curve.
- **TPR / FPR @ thr** uses each model's validation-calibrated threshold: 0.7298
  for v0, 0.8768 for v1.

| group | v0 AUC | v1 AUC | v0 TPR@FPR≤1% | v1 TPR@FPR≤1% | v0 TPR / FPR @ thr | v1 TPR / FPR @ thr |
|---|---|---|---|---|---|---|
| all | 0.976 | **0.984** | 0.485 | **0.625** | 0.957 / 0.074 | 0.930 / **0.035** |
| en | 0.978 | **0.988** | 0.486 | **0.838** | 0.957 / 0.069 | 0.927 / **0.014** |
| vi | 0.973 | **0.982** | 0.396 | **0.548** | 0.957 / 0.076 | 0.933 / **0.047** |
| vi orig | 0.994 | 0.998 | 0.827 | 0.981 | 0.976 / 0.042 | 0.995 / 0.013 |
| vi no_diacritics | 0.966 | 0.980 | 0.385 | 0.580 | 0.943 / 0.076 | 0.914 / 0.059 |
| vi teencode | 0.961 | 0.966 | 0.239 | 0.088 | 0.938 / 0.105 | 0.894 / 0.070 |

Per-category AUC for v1, with all benign rows of the language as negatives:

| | direct | indirect | jailbreak | extraction | exfiltration | tool poisoning | obfuscation |
|---|---|---|---|---|---|---|---|
| EN | 0.979 | 0.994 | 0.971 | 0.998 | 0.981 | 0.994 | 0.991 |
| VI | 0.992 | 0.991 | 0.975 | 0.983 | 0.972 | 0.968 | 0.980 |

Against the v0 comparison model, `protectai/deberta-v3-base-prompt-injection-v2`
(`reports/eval_report_v0.md`; it was not re-run), the AUCs are EN 0.897 and
VI 0.661.

Full tables are in `reports/eval_report_v1.{md,json}`.

## Latency

INT8 ONNX with onnxruntime 1.20.1 on CPU (Apple M3 Max), batch 1, model only.
v1 has the same architecture as v0, so the differences from v0 are
measurement noise.

| threads | 128 tokens p50 / p99 | 256 tokens p50 / p99 |
|---|---|---|
| default (14 cores) | 11.0 / 13.6 ms | 19.9 / 23.1 ms |
| 1 | 46.3 / 51.6 ms | 108.1 / 118.5 ms |

## Limitations

- **Vietnamese FPR is above target.** At the calibrated threshold it is
  4.7%, above the 1–2% target, and teencode (7.0%) and no-diacritics (5.9%)
  benign rows are still the weak spot. Vietnamese teencode TPR@FPR≤1% fell
  (0.24 → 0.09), although its AUC rose.
- **Recall at the deployed threshold fell 2–3 points** (0.957 → 0.93) because
  the threshold rose from 0.73 to 0.88. At equal FPR, recall is much higher
  than v0 (TPR@FPR≤1%: EN 0.49 → 0.84).
- **Synthetic Vietnamese.** The Vietnamese data is synthetic and
  agent-labelled, with no native-speaker review. Teencode comes from rules.
- **Thin `val_hard` recall.** `val_hard` has only 36 attacks, so it measures
  false positives far better than recall.
- **Template artefacts.** Most attacks are template-generated. Real attackers
  are more varied.
- **Per-label heads are advisory.** For example, `prompt_extraction` is the
  top-1 label for only 32% of EN extraction rows. Use the overall risk for
  decisions.
- **Truncation.** Inputs are cut at 256 tokens per window. The caller must
  window long inputs.
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
