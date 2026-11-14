# R8a holdout: arm E under `strong75_l2` on long8, scored once (RF-35fd836c)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

R8a followed [`r8a_preregistration.md`](r8a_preregistration.md) (commit `cce6a7b`) without changes. The dev
checks are in [`r8a_dev_checks.md`](r8a_dev_checks.md), and `long8` was pinned in `bench/long/corpus.yaml`
(`d60c49a`) before any score. No model was trained, exported or recalibrated, and no owner row left the laptop
(0 compute units).

The full numbers are in [`r8a_holdout.json`](r8a_holdout.json). The per-cell tables are in
`guardspec-data/v8/r8a/long8/r8a_holdout_longdoc.{json,md}` (not in git).

## Runs (2026-11-14, Apple M3 Max, ONNX INT8 on the CPU, binaries from `d60c49a`)

| model | `long8` benign (604 documents, 90.5M tokens) | `long8` attack (384 documents) |
|---|---|---|
| E | 17:43:53 to 19:16:04 | 19:16:04 to 20:08:08 |
| v6rel (record only) | 20:08:09 to 21:49:06 | 21:49:06 to 22:45:08 |

Each model was scored once. Arm E's eval/data hold-out slice (`gates/E/eval.json`, from R7's dev-stage run) was
read for the first time at the report stage.

## Verdict: E meets both sets of criteria

| criterion | E (`strong75_l2`) | set A | set B |
|---|---|---|---|
| 1. benign blocked ≤ 1% per size | 100k: **0 / 302** (CP95 0.0–1.2%); 200k: **1 / 300** (0.3%, CP95 0.0–1.8%) | met | 1': met (upper bounds ≤ 3%) |
| 2. embedded ≥ alone − 5 points | **285 / 324 (88.0%)** vs 44 / 48 (91.7%) alone: −3.7 points | met | 2': met; payload-clustered 95% interval of the difference −10.9 to +3.5 points |
| 3. eval/data hold-out TPR at FPR ≤ 1% ≥ 0.9432 | **0.9618** (602 attacks, 511 benign) | met | 3': met; FPR at 0.85 **0 / 511** (bar 0.0109) |

## Next to it

**Benign `long8` documents blocked (100k + 200k, 602 scored)**

| decision | E | v6rel |
|---|---|---|
| `strong75_l2` | **1** (0.2%) | 7 (1.2%) |
| `strong75` | 5 (0.8%) | 24 (4.0%) |
| `base` | 20 (3.3%) | 70 (11.6%) |

**Embedded attacks caught (324 intact embedded documents; the same 48 payloads alone: 91.7% for both models)**

| decision | E | v6rel |
|---|---|---|
| `strong75_l2` | **88.0%** (−3.7) | 78.1% (−13.6) |
| `strong75` | 90.7% (−0.9) | 86.7% (−4.9) |
| `base` | 92.0% (+0.3) | 89.2% (−2.5) |

- Under `strong75_l2`, E's lowest placements are `split_adjacent` (38 / 47, 80.9%) and `pos_end` (37 / 45,
  82.2%). Its highest are `straddle_window` and `straddle_segment` (43 / 46 each, 93.5%). By language, EN is
  86.1% (control 87.5%) and VI is 89.8% (control 95.8%).
- 3 of the 48 payloads are missed at every placement. 4 are missed alone.
- The released v6 under `strong75` blocks 24 of 602 documents (4.0%). That is the long-document state the
  gateway's documentation describes, and it is in line with R7's `long7` (10 / 180, 5.6%).

**eval/data hold-out, E against `ref`** (R7's `ref`, the same slice, read in R7)

| | E | `ref` |
|---|---|---|
| TPR at FPR ≤ 1% | 0.9618 (threshold 0.415) | 0.9618 (threshold 0.532) |
| TPR / FPR at 0.85 | 0.9369 / 0.0000 | 0.9502 / 0.0059 |
| gateway rule TPR / FPR | 0.9468 / 0.0000 | 0.9601 / 0.0059 |
| ROC AUC | 0.9894 | 0.9910 |

At the shipped threshold of 0.85, E catches 1.3 points fewer hold-out attacks than `ref` and blocks no hold-out
benign row. No criterion covers TPR at 0.85, so it is reported and not used.

## What was blocked or not scored

- **The one block under `strong75_l2`:** `long8-wiki-vi-200000-76`, a 200k-token Vietnamese Wikipedia document.
  One window has p 0.975, L1 0.959 and calibrated L2 0.982, so the L2 bar does not stop it.
- **The four documents `strong75` blocks and the bar removes:**
  - two Vietnamese 200k hard-negative documents;
  - one Vietnamese 100k hard-negative document;
  - one Vietnamese 200k Wikipedia document.

  Every blocking window there has calibrated L2 between 0.70 and 0.88, the band the review pointed at.
- **Two documents the sanitizer rejected:** `long8-docs-en-200000-5` and `-7`, both English technical
  documentation at 200k tokens. The rejection reason is "input exceeds 8 layers of encoding". The same happens
  for v6rel. As in every earlier long round (`longdoc_r5.measure`), they are left out of the denominators.

  A gateway that rejects an input refuses it, so a user sees these as blocks. Counted as blocked, 200k becomes
  3 / 302 (0.99%, CP95 upper 2.9%), and both sets are still met, with no margin left at 200k. This is a
  sanitizer limit, not a classifier result, and it applies to every model. It is reported for a follow-up and
  not counted in the verdict.

## Reading

- The L2 bar works as the review predicted on fresh text. It removes 4 of E's 5 `strong75` blocks and 17 of
  v6rel's 24, and costs E 2.7 points of embedded detection (v6rel: 8.6).
- E's eval/data hold-out TPR at FPR ≤ 1% equals `ref`'s, so the short-path loss R7 found for D does not show for
  E. At 0.85, E is a little more conservative than `ref` (fewer catches, no false positive).
- Every benign document E blocks under `strong75` or `strong75_l2` is Vietnamese. For E, the English half of
  `long8` has no block under either decision.
- With 300 documents per size, 0.2% overall is consistent with a true rate up to 0.9% (CP95 upper, all 602
  documents). "≤ 1%" is supported on this sample, not proven for every corpus.

## Limits and disclosure

- **One model, one decision, one sample.** E is a single training seed. R8b would be the place to test seeds
  (two seeds of `ref`, arm F).
- **Dev optimism.** L2_BAR was read off `long5`, which has been dev since R5. `long8` is fresh and is now spent.
- **The eval/data hold-out slice is not fresh.** It was read for `ref`, B, C and D in R6 and R7. A short-prompt
  claim for a release needs a fresh short-prompt holdout, which R8a does not provide.
- **INT8 only.** The FP32 check in `r8a_dev_checks.md` shows that FP32 blocks more on the long path (2 of 41
  `long5` documents against 0). The GPU (FP16) path needs its own `long8`-type measurement before any claim.
- **The decision is not in the gateway.** `ml.LongDoc` still applies `strong75`'s rules without the L2 bar. A
  release needs the bar in the gateway, a v8e package and the release process.
- **No-release commitment.** Nothing was packaged, published, tagged or uploaded, and `models/manifest.yaml`
  is unchanged.

## Follow-up (owner's decision)

- **v8e plus the long-path L2 bar** (proposed as a new task): put `strong75_l2` into `ml.LongDoc`, package E as
  a candidate in shadow mode, and measure the GPU path. A fresh short-prompt holdout is needed before E could
  become the default.
- **R8b (RF-a957551a):** arm F, two seeds of `ref` and the new criteria. The owner decides after this report.
- **The sanitizer's encoding-depth limit** on long technical documentation (2 of 302 English 200k documents).

## Reproduce

```sh
cd train
./run_r8a.sh holdout E      # refuses to run again: long8 is scored once per model
./run_r8a.sh holdout v6rel
./run_r8a.sh report         # -> reports/r8a_holdout.json
uv run --frozen python -m unittest tests.test_longdoc_r8a
```
