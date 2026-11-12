# v7 holdout: long6, scored once (RF-895d3533 R6)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

This applies the "Holdout (once)" section of [`v7_preregistration.md`](v7_preregistration.md) after
[`v7_dev.md`](v7_dev.md) was committed (3b7e26b). No arm qualified on dev, so the arm scored here is the
fallback candidate **C**: B with the mined hard negatives three times per epoch. Next to it are `ref` (v6 arm A
retrained on the L4) and the released v6 (MPS).

Every number is ONNX INT8 on the laptop's CPU. The pipeline is the R5 rules on the long path, the decisions
`strong75` (the evaluation decision) and `base`, n0 = 30, and each model's own calibration. CP95 is the
two-sided Clopper–Pearson interval.

- Benign: the 89 `long6` documents. `long6-wiki-en-200000-2` was left out before any scoring because an
  unrelated job had used it; see the disclosure in the pre-registration.
- Attacks: 48 payloads alone, and 336 embedded documents. The sanitizer removed the payload of 10 embedded
  documents, so 326 are counted, the same for every model.

Each model was scored once, with no rerun. The numbers are in `v7_holdout.json`.

## Verdict: **not met**

| criterion (pre-registered) | C | result |
|---|---|---|
| blocked benign ≤ 1% at 100k | 0 / 46 (0%, CP95 0–7.7%) | met (point estimate) |
| blocked benign ≤ 1% at 200k | 0 / 43 (0%, CP95 0–8.2%) | met (point estimate) |
| embedded detection ≥ alone − 5 points | 247 / 326 = 75.8% (70.7–80.3%) against 42 / 48 = 87.5% | **not met** (−11.7 points) |
| eval/data hold-out TPR at FPR ≤ 1% not below ref's CP95 low | 0.9385 against ref 0.9618 (CP95 low 0.9432) | **not met** |

With 46 and 43 documents, "0 blocked" only bounds the rate below about 8% at 95%. The 1% target is met as a
point estimate; it is not demonstrated. C fails the two detection criteria, as it did on dev. There is no v7.

## long6: C against ref against the released v6

| `strong75` (evaluation decision) | C | ref | released v6 |
|---|---|---|---|
| blocked benign, all | **0 / 89** (0–4.1%) | 6 / 89 (6.7%, 2.5–14.1%) | 4 / 89 (4.5%, 1.2–11.1%) |
| at 100k | 0 / 46 (0–7.7%) | 4 / 46 (8.7%, 2.4–20.8%) | 2 / 46 (4.3%, 0.5–14.8%) |
| at 200k | 0 / 43 (0–8.2%) | 2 / 43 (4.7%, 0.6–15.8%) | 2 / 43 (4.7%, 0.6–15.8%) |
| EN 100k, EN 200k, VI 100k, VI 200k | 0/26, 0/23, 0/20, 0/20 | 2/26, 1/23, 2/20, 1/20 | 1/26, 1/23, 1/20, 1/20 |
| benign windows blocking / scored | 0 / 67,993 | 7 / 67,993 | 5 / 67,993 |
| embedded detection | 247 / 326 = **75.8%** (70.7–80.3%) | 274 / 326 = 84.0% (79.6–87.9%) | 277 / 326 = 85.0% (80.6–88.7%) |
| payloads alone | 42 / 48 = 87.5% | 42 / 48 = 87.5% | 41 / 48 = 85.4% |
| embedded EN / VI | 75.6% / 75.9% | 81.1% / 87.0% | 82.9% / 87.0% |

| `base` (today's decision) | C | ref | released v6 |
|---|---|---|---|
| blocked benign, all | 2 / 89 (2.2%, 0.3–7.9%) | 17 / 89 (19.1%, 11.5–28.8%) | 11 / 89 (12.4%, 6.3–21.0%) |
| at 100k / at 200k | 1 / 46, 1 / 43 (both Vietnamese) | 10 / 46, 7 / 43 | 5 / 46, 6 / 43 |
| embedded detection | 262 / 326 = 80.4% (75.6–84.5%) | 288 / 326 = 88.3% (84.4–91.6%) | 289 / 326 = 88.7% (84.7–91.9%) |

Detection by placement, `strong75` (C / ref / v6):

| placement | C | ref | v6 |
|---|---|---|---|
| start | 81.2% | 81.2% | 87.5% |
| end | 80.4% | 87.0% | 87.0% |
| random | 71.7% | 84.8% | 84.8% |
| window boundary | 81.2% | 89.6% | 91.7% |
| chunk boundary | 76.1% | 84.8% | 82.6% |
| segment boundary | 80.9% | 85.1% | 85.1% |
| split adjacent | 57.8% | 75.6% | 75.6% |

eval/data hold-out slice (602 attacks / 511 benign, direct path, read only at this stage):

| | C | ref |
|---|---|---|
| TPR at FPR ≤ 1% | 0.9385 | 0.9618 |
| TPR / FPR at 0.85 | 0.9468 / 0.0215 | 0.9502 / 0.0059 |
| AUC | 0.9895 | 0.9910 |

## Reading

- **Benign long text works on benign long text.** The holdout confirms the dev result on new text and new
  sources. C blocks no `long6` document under `strong75`, and 2 under `base`, against 6 and 17 for `ref` and 4
  and 11 for the released v6. No benign window of 67,993 reaches a block. The R5 false-positive genres no
  longer trip the long path.
- **It costs detection.** C catches 8 to 9 points fewer embedded attacks than ref and v6 under both decisions:
  75.8% against 84.0% and 85.0% under `strong75`. The loss is largest where the payload sits in the middle of
  prose (random place, −13 points) or is split (−18 points), and payloads alone are unchanged. C also loses
  2.3 points of eval/data hold-out TPR at FPR ≤ 1%, and its FPR at 0.85 is 2.15% against 0.59%. C learnt to
  discount instructions surrounded by long prose, not only to recognise benign prose.
- **Holdout matches dev.** The ranking and the size of the effects are the same as on long5 (dev: C 0 / 150
  blocked, embedded 77.6%; ref 13 / 150, 87.2%). ref against v6 differs by 2 documents here and 4 on dev,
  which is the noise between two trainings of one recipe.
- **What this means for R6.** The 1% document target is reachable by training with benign long text, but this
  recipe pays for it with detection the pre-registration does not allow. Both criteria together need a training
  set that keeps context from being a benign signal, for example benign and attack windows from the same long
  hosts in equal measure, or a smaller, weighted benign addition. Any such recipe needs a new pre-registration
  and a new holdout: `long6` is spent.

## Notes

- **Not pre-registered: B's eval/data hold-out slice.** While reading the eval/data hold-out slices for C and
  ref, I also printed arm B's: TPR at FPR ≤ 1% 0.9485, TPR / FPR at 0.85 0.9485 / 0.0098. The pre-registration
  names only the chosen arm and ref. It changes nothing, since no rule reads it after the decision, but it is
  disclosed here.
- **Unchanged:** no model is packaged or published. MODEL_CARD and docs/benchmark are unchanged because nothing
  ships. `guardspec-data/v7/work/holdout/` holds the dumps (scores only) and `v7_holdout_longdoc.{json,md}`.
