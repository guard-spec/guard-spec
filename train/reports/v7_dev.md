# v7 dev result (RF-895d3533 R6)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

The rule of [`v7_preregistration.md`](v7_preregistration.md), applied unchanged by `select_v7.py`
(`v7_dev.json`) and `longdoc_v7.py`. Every number comes from ONNX INT8 on the CPU of the Apple M3 Max laptop,
with the rule set of this branch (the R5 `r5` rules). The models were trained on a Colab L4 (`train_arms_v7.json`).
Written before any `long6` file was opened or scored.

## Result: no arm qualifies, so there is no v7

Both v7 arms remove every blocked long5 document. Both fail **LD-TPR**: with the `strong75` decision,
detection of attacks embedded in long documents falls more than 5 points below detection of the same payloads
alone. B also fails **G6**: it blocks 1 of the 15 bench/long full-profile dev documents of 100k and 200k tokens.
C meets 9 of the 10 gates and B 8, so **C is the fallback candidate**. As pre-registered, `long6` is still
scored once for C, `ref` and the released v6, for the record. Nothing is packaged as v7.

## Gates (dev)

| gate | ref (v6 on L4) | B (+ v7_train) | C (B, hard negatives × 3) | limit |
|---|---|---|---|---|
| G1 eval/data dev TPR at FPR ≤ 1% (direct) | 0.9473 ✓ | 0.9315 ✓ | 0.9297 ✓ | ≥ v3b 0.9086 |
| G2 eval/codelog dev FPR at 0.85 (tool, corroboration off) | 0.0203 ✓ | 0.0068 ✓ | 0.0068 ✓ | ≤ 0.03 |
| G3 eval/embedded dev TPR at 0.85 | 0.9174 ✓ | 0.9192 ✓ | 0.9156 ✓ | ≥ v3b 0.8067, L1 0.8506 |
| G4 eval/embedded dev FPR at 0.85 | 0.0344 ✓ | 0.0243 ✓ | 0.0263 ✓ | ≤ v3b 0.1053 |
| G5 val_v3 TPR at 0.85 (31 attacks) | 1.000 ✓ | 1.000 ✓ | 1.000 ✓ | ≥ v3b 0.9355 − 0.01 |
| G6 bench/long full dev, blocked 100k + 200k (15 docs) | 0 ✓ | **1 ✗** (en 200k) | 0 ✓ | ≤ 1% |
| G7 bench/long full dev, in prose vs alone | 0.933 vs 0.969 ✓ | 0.893 vs 0.906 ✓ | 0.897 vs 0.906 ✓ | ≥ alone − 0.05 |
| G8 eval/data dev TPR at FPR ≤ 1% vs ref's CP95 low (0.9256) | 0.9473 ✓ | 0.9315 ✓ | 0.9297 ✓ | ≥ 0.9256 |
| LD-TPR long5 embedded vs alone (`strong75`) | 0.872 vs 0.888 ✓ | **0.807 vs 0.875 ✗** | **0.776 vs 0.875 ✗** | ≥ alone − 0.05 |
| LD-REF long5 blocked (`strong75`), fewer than ref | 13 (reference) | 0 ✓ | 0 ✓ | < 13 |
| gates met (of 10) | - | 8 | **9** | |

## Long documents, long5 (both halves, 150 benign 100k/200k documents; R5 attack documents, 554 embedded + 80 alone)

r5 rules on the long path; n0 = 30; each model with its own calibration. CP95 is two-sided Clopper–Pearson.

| | ref | B | C | released v6 (MPS) |
|---|---|---|---|---|
| `strong75` blocked benign, all | 13 / 150 (8.7%, 4.7–14.4%) | **0 / 150** (0–2.4%) | **0 / 150** (0–2.4%) | 9 / 150 (6.0%, 2.8–11.1%) |
| at 100k / at 200k | 4 / 75, 9 / 75 | 0 / 75, 0 / 75 | 0 / 75, 0 / 75 | 4 / 75, 5 / 75 |
| EN / VI (100k + 200k) | 11, 2 | 0, 0 | 0, 0 | 6, 3 |
| benign windows blocking / scored | 22 / 116,245 | 0 / 116,245 | 0 / 116,245 | 19 / 116,245 |
| `strong75` embedded detection | 483 / 554 = 87.2% (84.1–89.9%) | 447 / 554 = 80.7% (77.2–83.9%) | 430 / 554 = 77.6% (73.9–81.0%) | 87.2% |
| payloads alone | 71 / 80 = 88.8% | 70 / 80 = 87.5% | 70 / 80 = 87.5% | 68 / 80 = 85.0% |
| `base` blocked benign | 25 / 150 | 2 / 150 | 4 / 150 | 18 / 150 |
| `base` embedded detection | 500 / 554 = 90.3% | 460 / 554 = 83.0% | 443 / 554 = 80.0% | - |

Detection per placement, `strong75` (ref / B / C): start 88.7 / 80.0 / 76.2%, end 87.0 / 85.7 / 85.7%, random
85.9 / 79.5 / 75.6%, window boundary 91.1 / 79.7 / 75.9%, chunk boundary 93.8 / 81.2 / 80.0%, segment boundary
88.7 / 85.0 / 78.7%, split adjacent 75.0 / 73.8 / 71.3%.

## Reading

- **What the benign long text does.** Adding 11,270 benign long-text windows removes every blocked long5
  document under both decisions. Under `strong75`, not one of 116,245 benign windows blocks for B or C, against
  22 for ref. That is the per-window rate below 10⁻⁵ that the 1% target needs.
- **The cost.** Embedded payloads are caught less often, by 6.5 points for B and 9.6 for C under `strong75`
  (against 3.6 and 7.7 points under `base`). Payloads alone barely move (87.5% against 88.8%). So the model
  has learnt to lower its scores for prose context around a payload, rather than to recognise benign text only.
  Oversampling the mined hard negatives three times per epoch (C) costs more detection and gains nothing on
  benign text. The criterion is pre-registered against the decision `strong75`. Under `base`, B would pass it
  (83.0% against 82.5%) but block 2 documents. That is recorded, not used: the rule is not changed after the
  numbers.
- **Noise.** Two trainings of the same recipe on the same data differ: ref (L4) blocks 13 / 150 long5
  documents and the released v6 (MPS) 9 / 150, about 4 documents apart. LD-REF compares against one ref
  training, so a difference of a few documents between arms would not be meaningful. The difference here
  (0 against 13) is far larger than that noise. The detection loss (about 40 to 50 of 554 documents) is also
  larger than the ref-against-v6 spread on detection (0 documents).
- **Next steps (outside R6).** Each option needs its own pre-registration:
  - fewer benign windows, or a lower weight for them;
  - paired benign and attack windows from the same long hosts, so that context alone stops being a benign
    signal;
  - a decision that does not need L1 at the 0.75 bar for embedded payloads.

## Files

- `v7_dev.json`: every gate and long-document number per arm.
- `guardspec-data/v7/work/select/v7_dev_longdoc.{json,md}`: the long5 tables per decision, with v6rel.
- `train_arms_v7.json`: the training jobs.
