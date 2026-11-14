# v8 dev result (RF-3a9ce3f9 R7)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

`select_v8.py` (`v8_dev.json`) and `longdoc_v8.py` applied the rule of
[`v8_preregistration.md`](v8_preregistration.md) without changes. Every number comes from ONNX INT8 on the CPU
of the Apple M3 Max laptop. All models were scored with the same binaries, built from 019b47b with the R5 `r5`
rules: `ref`, the released v6, v3b and L1 alone. D and E were trained on a Colab L4 (`train_arms_v8.json`).
This report was written before any `long7` file was opened or scored.

## Result: no arm qualifies, so there is no v8

Both arms pass **LD-TPR**, which R6 failed. Detection of attacks embedded in long documents is now at least
detection of the same payloads alone (`strong75`: D 87.2% against 86.2%, E 88.1% against 86.2%). Both arms also
pass **LD-REF**. Each arm fails one other gate:

- **D** fails **G8**. Its eval/data dev TPR at FPR ≤ 1% is 0.9086, below the lower end of `ref`'s CP95 interval
  (0.9256; `ref` 0.9473). This is the same short-path cost R6 saw.
- **E** fails **G6**. It blocks 3 of the 15 bench/long full-profile dev documents of 100k and 200k tokens (en 200k,
  vi 100k, vi 200k).

Both arms meet 9 of the 10 gates. The fallback order first counts gates met, which is a tie. The next key is the
number of blocked long5 documents under `strong75`: D blocks 0 and E blocks 4. So **D is the fallback
candidate**. D also meets the dev target LD-FPR (0 of 150 blocked, at most 1 allowed). As pre-registered,
`long7` is still scored once for D, `ref` and the released v6, for the record. Nothing is packaged as v8.

## Gates (dev)

| gate | ref (v6 on L4) | D (+ v8_train, 1:1) | E (+ v8e_train, half the benign) | limit |
|---|---|---|---|---|
| G1 eval/data dev TPR at FPR ≤ 1% (direct) | 0.9473 ✓ | 0.9086 ✓ | 0.9455 ✓ | ≥ v3b 0.9086 |
| G2 eval/codelog dev FPR at 0.85 (tool, corroboration off) | 0.0203 ✓ | 0.0000 ✓ | 0.0203 ✓ | ≤ 0.03 |
| G3 eval/embedded dev TPR at 0.85 | 0.9174 ✓ | 0.9104 ✓ | 0.9244 ✓ | ≥ v3b 0.8067, L1 0.8506 |
| G4 eval/embedded dev FPR at 0.85 | 0.0344 ✓ | 0.0324 ✓ | 0.0425 ✓ | ≤ v3b 0.1053 |
| G5 val_v3 TPR at 0.85 (31 attacks) | 1.000 ✓ | 1.000 ✓ | 1.000 ✓ | ≥ v3b 0.9355 − 0.01 |
| G6 bench/long full dev, blocked 100k + 200k (15 docs) | 0 ✓ | 0 ✓ | **3 ✗** (en 200k, vi 100k, vi 200k) | ≤ 1% |
| G7 bench/long full dev, in prose vs alone | 0.933 vs 0.969 ✓ | 0.960 vs 0.938 ✓ | 0.964 vs 0.969 ✓ | ≥ alone − 0.05 |
| G8 eval/data dev TPR at FPR ≤ 1% vs ref's CP95 low (0.9256) | 0.9473 ✓ | **0.9086 ✗** | 0.9455 ✓ | ≥ 0.9256 |
| LD-TPR long5 embedded vs alone (`strong75`) | 0.872 vs 0.888 ✓ | 0.872 vs 0.863 ✓ | 0.881 vs 0.863 ✓ | ≥ alone − 0.05 |
| LD-REF long5 blocked (`strong75`), fewer than ref | 13 (reference) | 0 ✓ | 4 ✓ | < 13 |
| gates met (of 10) | - | **9** | 9 | |

G1 for D equals v3b's value: both are 517 of 569 attacks, from different models with different thresholds
(0.9271 and 0.8985).

## Long documents, long5 (both halves; 150 benign documents of 100k and 200k tokens; R5 attack documents, 554 embedded and 80 alone)

The long path uses the r5 rules and n0 = 30, and each model uses its own calibration. CP95 is the two-sided
Clopper–Pearson interval.

| | ref | D | E | released v6 (MPS) |
|---|---|---|---|---|
| `strong75` blocked benign, all | 13 / 150 (8.7%, 4.7–14.4%) | **0 / 150** (0–2.4%) | 4 / 150 (2.7%, 0.7–6.7%) | 9 / 150 (6.0%, 2.8–11.1%) |
| at 100k / at 200k | 4 / 75, 9 / 75 | 0 / 75, 0 / 75 | 2 / 75, 2 / 75 | 4 / 75, 5 / 75 |
| EN / VI (100k + 200k) | 11, 2 | 0, 0 | 3, 1 | 6, 3 |
| benign windows blocking / scored | 22 / 116,245 | 0 / 116,245 | 4 / 116,245 | 19 / 116,245 |
| `strong75` embedded detection | 483 / 554 = 87.2% (84.1–89.9%) | 483 / 554 = 87.2% (84.1–89.9%) | 488 / 554 = 88.1% (85.1–90.7%) | 483 / 554 = 87.2% |
| payloads alone | 71 / 80 = 88.8% | 69 / 80 = 86.2% | 69 / 80 = 86.2% | 68 / 80 = 85.0% |
| `base` blocked benign | 25 / 150 | 3 / 150 | 10 / 150 | 18 / 150 |
| `base` embedded detection | 500 / 554 = 90.3% | 496 / 554 = 89.5% | 498 / 554 = 89.9% | 495 / 554 = 89.4% |

Detection per placement under `strong75` (ref / D / E):

| placement | ref | D | E |
|---|---|---|---|
| start | 88.8% | 83.8% | 85.0% |
| end | 87.0% | 89.6% | 89.6% |
| random | 85.9% | 87.2% | 89.7% |
| window boundary | 91.1% | 89.9% | 91.1% |
| chunk boundary | 93.8% | 91.2% | 88.8% |
| segment boundary | 88.8% | 90.0% | 92.5% |
| split adjacent | 75.0% | 78.8% | 80.0% |

## Reading

- **What the paired data does.** An attack window from the same host next to each benign window removed R6's
  failure. D blocks no long5 document and no benign window, as R6's B and C did. Its embedded detection is
  `ref`'s (483 of 554), against 447 for B and 430 for C. The weak spots of R6 improved over `ref`: mid-prose
  (random) 87.2% against 85.9%, split adjacent 78.8% against 75.0%. Only the start placement is lower (83.8%
  against 88.8%).
- **The cost moved to the short path.** D's eval/data dev TPR at FPR ≤ 1% falls from 0.9473 to 0.9086. B and C
  in R6 lost less (0.9315, 0.9297) and passed G8. The long-path gains do not carry over to short prompts at the
  1% operating point.
- **Less benign mass (E) protects the short path but brings blocks back.** E keeps G8 (0.9455) and has the best
  embedded detection. But it blocks 4 long5 documents and 3 of the 15 full-profile dev documents. Halving the
  benign rows gives up part of the false-positive gain.
- **Noise.** As in R6, one training per arm. The ref (L4) and released v6 (MPS) runs of the same recipe differ by
  4 blocked long5 documents. D's G8 gap is 22 of 569 attacks against `ref` (517 against 539), 0.017 below the
  CP95 low. E's G6 failure is 3 of 15 documents. The rule is applied as written: neither failure is waived.
- **Next steps (outside R7).** Each option needs its own pre-registration:
  - D's data with short-prompt hard positives up-weighted, to recover eval/data at FPR ≤ 1%;
  - a benign fraction between E's (0.5) and D's (1.0);
  - a per-arm check of where D loses eval/data TPR (which groups and languages) before the next design.

## Files

- `v8_dev.json`: every gate and long-document number per arm.
- `guardspec-data/v8/work/select/v8_dev_longdoc.{json,md}`: the long5 tables per decision, with v6rel (not in git).
- `train_arms_v8.json`: the training jobs (Colab L4, 3.79 compute units).
