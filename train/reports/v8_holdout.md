# v8 holdout: long7, scored once (RF-3a9ce3f9 R7)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

This report applies the "Holdout (once)" section of [`v8_preregistration.md`](v8_preregistration.md). It was
run after [`v8_dev.md`](v8_dev.md) was committed (9d4e4ae) and reviewed. No arm qualified on dev, so the arm
scored here is the fallback candidate **D**: `ref` + `v8_train.jsonl`, with long benign windows and one
attack window from the same host for each. It is compared with `ref` (v6 arm A retrained on the L4) and the
released v6 (MPS).

Every number is ONNX INT8 on the laptop's CPU, with the same `cmd/benchlong` and `cmd/eval` binaries as dev
(built from 019b47b). The pipeline is the R5 rules on the long path, the decisions `strong75` (the evaluation
decision) and `base`, n0 = 30, and each model's own calibration. CP95 is the two-sided Clopper–Pearson interval.

- Benign: the 180 `long7` documents (45 per language and size).
- Attacks: 48 payloads alone, and 336 embedded documents. The sanitizer removed the payload of 9 embedded
  documents, so 327 are counted for every model.

Each model was scored once, with no rerun, in about 4 hours of laptop time (21:56 to 01:55). The eval/data hold-out
slice was read only at this stage, and only for D and `ref`. The numbers are in `v8_holdout.json`.

## Verdict: **not met**

| criterion (pre-registered) | D | result |
|---|---|---|
| 1. blocked benign ≤ 1% at 100k (0 of 90) | 1 / 90 (1.1%, CP95 0.03–6.0%) | **not met** |
| 1. blocked benign ≤ 1% at 200k (0 of 90) | 1 / 90 (1.1%, CP95 0.03–6.0%) | **not met** |
| 2. embedded detection ≥ alone − 5 points | 311 / 327 = 95.1% (92.2–97.2%) against 45 / 48 = 93.8% | met (+1.4 points) |
| 3. eval/data hold-out TPR at FPR ≤ 1% not below ref's CP95 low | 0.9352 against ref 0.9618 (CP95 low 0.9432) | **not met** |

Both blocked documents are English, one at 100k and one at 200k. D meets the detection criterion that R6
failed, but it misses the document target by one document per size. It also misses the short-path criterion,
as G8 predicted on dev. There is no v8.

## long7: D against ref against the released v6

| `strong75` (evaluation decision) | D | ref | released v6 |
|---|---|---|---|
| blocked benign, all | **2 / 180** (1.1%, 0.1–4.0%) | 12 / 180 (6.7%, 3.5–11.4%) | 10 / 180 (5.6%, 2.7–10.0%) |
| at 100k / at 200k | 1 / 90, 1 / 90 | 4 / 90, 8 / 90 | 3 / 90, 7 / 90 |
| EN 100k, EN 200k, VI 100k, VI 200k | 1/45, 1/45, 0/45, 0/45 | 3/45, 4/45, 1/45, 4/45 | 3/45, 4/45, 0/45, 3/45 |
| benign windows blocking / scored | 5 / 136,861 | 15 / 136,861 | 15 / 136,861 |
| embedded detection | **311 / 327 = 95.1%** (92.2–97.2%) | 300 / 327 = 91.7% (88.2–94.5%) | 302 / 327 = 92.4% (88.9–95.0%) |
| payloads alone | 45 / 48 = 93.8% | 47 / 48 = 97.9% | 44 / 48 = 91.7% |
| embedded EN / VI | 93.1% / 97.0% | 89.4% / 94.0% | 89.4% / 95.2% |

| `base` | D | ref | released v6 |
|---|---|---|---|
| blocked benign, all | 4 / 180 (2.2%, 0.6–5.6%) | 21 / 180 (11.7%, 7.4–17.3%) | 22 / 180 (12.2%, 7.8–17.9%) |
| at 100k / at 200k | 2 / 90, 2 / 90 | 7 / 90, 14 / 90 | 6 / 90, 16 / 90 |
| embedded detection | 316 / 327 = 96.6% (94.1–98.3%) | 308 / 327 = 94.2% (91.1–96.5%) | 310 / 327 = 94.8% (91.8–96.9%) |

Detection by placement under `strong75`:

| placement | D | ref | v6 |
|---|---|---|---|
| start | 93.8% | 97.9% | 97.9% |
| end | 97.8% | 93.5% | 95.7% |
| random | 95.6% | 91.1% | 88.9% |
| window boundary | 97.9% | 93.6% | 95.7% |
| chunk boundary | 93.8% | 89.6% | 89.6% |
| segment boundary | 95.7% | 87.2% | 91.5% |
| split adjacent | 91.3% | 89.1% | 87.0% |

eval/data hold-out slice (602 attacks, 511 benign, direct path, read only at this stage):

| | D | ref |
|---|---|---|
| TPR at FPR ≤ 1% | 0.9352 | 0.9618 |
| TPR / FPR at 0.85 | 0.9419 / 0.0157 | 0.9502 / 0.0059 |
| AUC | 0.9884 | 0.9910 |

## Reading

- **The paired data fixed R6's detection loss.** On new hosts and payloads, D detects more embedded attacks
  than `ref` and the released v6 under both decisions: 95.1% under `strong75`, against 91.7% and 92.4%. It
  gains most where R6's C lost most: mid-prose (random place) +4.5 points and split adjacent +2.2 points over
  `ref`. R6's C was 13 and 18 points below `ref` there.
- **It cuts blocked long documents by about 6x, but not to zero.** Under `strong75`, D blocks 2 of 180
  documents, against 12 for `ref` and 10 for v6. Under `base` it blocks 4, against 21 and 22. The target needs
  0 of 90 at each size. With 1 of 90 at each, the CP95 upper bound is 6%, so the 1% target is neither met
  nor ruled out.
- **The short-path cost is real.** On the eval/data hold-out slice, D loses 2.7 points of TPR at FPR ≤ 1%
  (0.9352 against 0.9618), and its FPR at 0.85 is 1.57% against 0.59%. This matches dev (G8: 0.9086 against
  0.9473) and is about the same as R6's C on the same slice (0.9385). Adding long-window data, paired or not,
  costs short-prompt separation at the 1% operating point.
- **Holdout matches dev.** On long5, D blocked 0 of 150 and detected 87.2% embedded against 86.2% alone, while
  ref blocked 13 of 150. On long7, the ranking is the same. ref against v6 differs by 2 documents, as in R6.
- **For a later round (outside R7).** The long-path recipe works. What is left is the short-path loss, plus
  2 documents. Each option needs its own pre-registration and a new holdout, because `long7` is now spent:
  - up-weight or add short-prompt hard positives next to `v8_train.jsonl`;
  - calibrate the long path separately from the short path.

## Notes

- **No deviation.** Only the three pre-registered models were scored on `long7`. Only D's and ref's
  eval/data hold-out slices were read, and no other holdout was opened. Every model was scored with the dev
  binaries. Commits after 019b47b change only reports, so the binary directories for those commits point at
  the 019b47b build.
- **Unchanged:** no model is packaged or published, and `models/manifest.yaml`, MODEL_CARD and
  docs/benchmark are untouched. `guardspec-data/v8/work/long7/` holds the dumps (scores only) and
  `v8_holdout_longdoc.{json,md}`.
