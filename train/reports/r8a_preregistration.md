# R8a pre-registration: R7's arm E under the long-path decision `strong75_l2`, long8 as the holdout (RF-35fd836c)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-14, before the `long8` profile exists, before any `long8` document is built or scored, and
before arm E's eval/data hold-out slice is read. `train/longdoc_r8a.py` implements the decision below; its
constants are the values here. No model is trained in R8a (0 compute units, no Colab job, no owner row leaves
the laptop).

## Problem and hypothesis

R7 (`v8_holdout.md`) did not meet its target. An independent review after R7 (Resolflow research document
"Review độc lập model phát hiện tài liệu dài sau R7 (đề xuất R8)") found:

- On benign long text, the remaining long-path blocks of the v8 arms are windows where an L1 rule of weight
  0.75 or more fires and the calibrated L2 sits between 0.80 and 0.96. Payload windows of the v8 arms sit
  higher: the 25th percentile of the calibrated L2 of the best payload window is 0.976 to 0.983, against 0.949
  for `ref`.
- `strong75` never asks L2 for more than 0.5 (through the `agree` clause on floors), so it does not use that gap.
- Arm E (`ref` + `v8e_train.jsonl`: every v8 attack row and a seeded half of the v8 benign rows) kept the short
  path on dev (G8: 0.9455 against `ref`'s CP95 low 0.9256). R7 ruled it out on G6 (3 of 15 bench/long full
  documents, a different pipeline from the long path) and on 4 of 150 blocked `long5` documents under
  `strong75`. Its eval/data hold-out slice has never been read.

**Hypothesis.** Arm E under `strong75` plus a calibrated-L2 bar of 0.95 on the long path keeps blocked benign
long documents at or below 1% at 100k and at 200k tokens on fresh text. It also keeps embedded detection within
5 points of the same payloads alone.

## Candidate and comparator (fixed)

| name | model | `model_int8.onnx` SHA-256 |
|---|---|---|
| **E** (candidate) | `guardspec-data/v8/work/runs/E/model` (R7 job `v8-E`, exported and calibrated in R7) | `447c63cd6f2378c957b3282a1d4526f00feef9153e0046203c10fb20d75d7dde` |
| v6rel (record only) | the released v6, `guardspec-data/v6/release/guardspec-classifier-v6` | `be5fba5b2c94fdbb20a628002cadde2857349dbb6092e3690ba41d6bcd347f29` |

E's `calibration.json` SHA-256 is `51ac3c2d2bb744219b915d33ae3b3f17584b9162e84f58c99bf4ee9453dc1c3d`. Nothing is
retrained, re-exported or recalibrated. `ref` and D are not scored on `long8`. They have no role in the R8a
criteria, and laptop time goes to the larger holdout instead.

## Decision (fixed)

The R5 rule set (`r5`), the long path of `cmd/benchlong -long on`, n0 = 30, and each model's own calibration
are as in R7.

- **`strong75_l2`** (the R8a evaluation decision). A window of a text of more than n0 windows blocks when:
  - it blocks under `strong75`, and
  - its calibrated L2 is at least **L2_BAR = 0.95**.

  Texts of at most n0 windows keep `base`, as under every decision; this covers the payloads alone.
- `strong75` and `base` are reported next to it.

How L2_BAR was set: the review chose 0.95 on `long5` dev. On `long5` (both halves), `train/longdoc_r8a.py
--stage dev` gives the following (written to `guardspec-data/v8/r8a/dev/`, reproduced on 2026-11-14):

| `long5`, 150 benign documents, 554 embedded, 80 alone | blocked | embedded vs alone | payload-clustered 95% interval of the difference |
|---|---|---|---|
| E `strong75_l2` | 0 / 150 | 0.868 vs 0.863 | −0.046 to +0.064 |
| E `strong75` | 4 / 150 | 0.881 vs 0.863 | −0.033 to +0.076 |
| D `strong75_l2` | 0 / 150 | 0.847 vs 0.863 | −0.069 to +0.038 |
| ref `strong75_l2` | 3 / 150 | 0.717 vs 0.887 | −0.233 to −0.113 |
| v6rel `strong75_l2` | 3 / 150 | 0.776 vs 0.850 | −0.122 to −0.027 |

L2_BAR is not changed after this commit.

## Holdout: `long8` (built after this commit)

`bench/long/corpus.yaml` profile `long8`, committed after this file and before any score.

**Benign documents**
- 100k and 200k tokens, **at least 300 documents per size**, about 150 English and 150 Vietnamese per size.
  If a language's pool runs out, it has at least 100 per size, and the other language fills the rest.
- Sources come from no other profile (quick, full, long, long5, long6, long7) and from no v4-A, v6, v7 or v8
  training or validation row, nor from the v7 pool (the v8 hosts).
- Units that share a 50-token run with any of those are listed in `bench/long/exclude.json` and dropped, as
  are units that near-duplicate (20% of their 50-token shingles) an earlier profile's document.
- Synthetic genres use a new seed.
- `outputs.long8` pins the SHA-256 of `docs.jsonl`.

**Attack documents**
- Built with `bench/long/embed_long.py --eval-payloads 24 --eval-skip 120` on `long8` hosts of the same
  language, dev and holdout splits concatenated.
- These are eval/ dev-half attack rows 120 to 143 per language in build.py's seeded order, disjoint from `full`
  (0–31), R5 (32–71), `long6` (72–95) and `long7` (96–119).
- That gives 48 payloads, 48 payloads alone, and 336 embedded documents (seven placements).
- Their SHA-256 is written into `corpus.yaml` next to the profile before any score.

**Scoring rules**
- Every `long8` document is R8a holdout, whatever its `split` field says.
- Every number is ONNX INT8 on the laptop's CPU, with `cmd/benchlong` and `cmd/eval` built from one commit made
  after `long8` is pinned.
- E and v6rel are each scored once on `long8`, with start and end times in the report.
- Arm E's eval/data hold-out slice is read once, at the same stage. It comes from the R7 dev-stage `cmd/eval`
  report (`guardspec-data/v8/work/gates/E/eval.json`), which no one has read.

## Criteria

R8a reports a verdict under both sets of criteria. The proposed set needs the owner's agreement before it can
replace the R7 criteria for any release decision.

**Set A: R7's criteria**, unchanged except for the sample size:

1. Blocked benign documents ≤ 1% at 100k and at 200k tokens on `long8` (E, `strong75_l2`). With 300 documents
   per size, that is at most 3 at each size.
2. Embedded detection ≥ detection of the same payloads alone − 5 points (E, `strong75_l2`, pooled, intact
   embedded documents).
3. eval/data hold-out TPR at FPR ≤ 1% ≥ **0.9432**, the lower end of `ref`'s two-sided CP95 interval as R7
   reported it (`v8_holdout.md`: `ref` 0.9618).

**Set B: proposed by the review**

- 1'. As 1, and the two-sided Clopper–Pearson 95% upper bound at each size is ≤ 3%.
- 2'. As 2, on the point estimate. The 95% interval of the difference is also reported, from a bootstrap over
  the 48 payloads (10,000 resamples, seed 20261114). It is reported, not a condition.
- 3'. As 3, and eval/data hold-out FPR at 0.85 ≤ **0.0109** (`ref`'s 0.0059 in `v8_holdout.md` + 0.5 point).

G1–G8, LD-TPR and LD-REF are R7's selection gates. R8a selects nothing (E is fixed above), so none of them is
applied. G6 in particular is not used. E's R7 dev gate values stand as reported in `v8_dev.md`.

## Dev checks before `long8` (explanation only)

These checks run on dev data only. They cannot change L2_BAR, the candidate or the criteria. Their results go
into `r8a_dev_checks.md` before `long8` is scored.

- (a) The eval/data **dev** benign rows that D and E block at 0.85 (`gates/{D,E}/eval.json`, dev slice):
  their categories, to test the review's hypothesis that v8's pairing taught "instruction = attack".
- (b) E's FP32 ONNX (`runs/E/model_fp32.onnx`) on the `long5` benign windows with calibrated INT8 L2 ≥ 0.80:
  how many cross 0.95 in one precision and not the other.

## Disclosure

- `long5` has been dev for R5, R6, R7 and now R8a, and L2_BAR was read off it, so dev numbers are optimistic.
  `long8` is the measure.
- During the review, the reviewer read one aggregate from the spent `long7` D dump: the `(l1, l2, p, rule ids)`
  of the 8 benign windows at or above 0.85 (no text, no document ids). Nothing else from `long6` or `long7`, no
  owner row and no timing file was read. The review read the `long5` dumps of D, E, `ref` and v6rel, and the
  dev slice of `gates/*/eval.json`.
- The eval/data hold-out slice is not fresh. It was read for `ref`, B, C and D in R6 and R7. eval/data dev has
  been the selection target since v3. A short-prompt claim for a release needs a fresh short-prompt holdout;
  R8a does not provide one.

## Implementation commitment

- Nothing is packaged, published, tagged or uploaded.
- `models/manifest.yaml`, the gateway's `ml.LongDoc` and the default model are unchanged.
- If E meets either set, a follow-up task proposes v8e with the L2 bar on the long path, for the owner to
  decide.
- Whatever the result, the owner decides on R8b (RF-a957551a) after the report.
