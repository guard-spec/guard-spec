# v8 pre-registration: long benign and embedded-attack windows of the same hosts, long5 as dev, long7 as the holdout (RF-3a9ce3f9, R7)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-13, before any v8 training run, before any `long7` document or `long7` attack document was
scored by a model or a rule layer, and before `v8_train.jsonl` or `v8e_train.jsonl` was scored by anything.
`train/select_v8.py`, `train/longdoc_v8.py` and `train/run_arms_v8.sh` (9f603d9) implement every definition
here; their constants are the values below. `reports/train_arms_v8.json` holds the job plan; its results are
filled in after each job. The `long7` corpus (`bench/long/corpus.yaml`, profile `long7`, ea80631) and the
v8 data (`train/data/build_v8.py`, `train/data/stats_v8.json`, 6f8fa55 and 8e4703a) were committed before this
file.

## Problem and target

R6 (`v7_preregistration.md`, `v7_dev.md`, `v7_holdout.md`) added 11,270 benign windows of long text to training.
On the `long6` holdout the fallback arm C blocked 0 of 89 benign documents under `strong75` (ref 6, the released
v6 4), but detection of attacks embedded in long documents fell to 75.8% against 87.5% for the payloads alone
and 85.0% for v6 (a payload in the middle of prose −13 points, a split payload −18 points), and its eval/data
hold-out TPR at FPR ≤ 1% was 0.9385 against `ref`'s 0.9618. The model learnt that prose around an instruction
is a benign signal. R6 is "not met"; `long6` is spent.

Target (unchanged from R6): on the long path with the R5 evaluation pipeline (below), blocked benign documents
at most 1% at 100k and at 200k tokens; detection of attacks embedded in long documents at least the stand-alone
detection of the same payloads minus 5 points; `eval/data` not below the reference.

## What changes against R6, and why

- **Balanced, same-host data.** v8 keeps every v7 benign window (`v8_benign`) and adds one attack window cut
  from the same host for each (`v8_attack`): 11,270 : 11,270 rows (EN 6,920 + 6,920, VI 4,350 + 4,350), 13,307 :
  11,501 gateway windows (1.16). In R6 all long text was benign, so "long prose" alone predicted the label; with
  the same hosts on both sides it no longer does, and the model has to find the instruction.
- **Placement mix weighted to R6's weak spots** (`sources_v8.yaml`): mid-prose 30.7%, split within one window
  15.1%, split with a bridge sentence 14.4%, straddling the gateway window boundary 13.6%, start 13.0%, end
  13.1%. R6 lost most where the payload sits mid-prose or is split.
- **No hard-negative oversampling arm.** R6's C (hard negatives × 3) lost the most detection; the v7 hard
  negatives are kept once, inside `v8_benign`, with an attack partner of their own.
- **A second arm with less benign mass (E).** E keeps every attack row and a seeded half of the benign rows
  (5,636 : 11,270 rows, 7,023 : 11,501 windows = 0.61), to see whether the false-positive gain survives with a
  smaller benign addition while detection is protected more.
- **The reference is not retrained.** `ref` is R6's GPU reference model itself (job `v7-ref`), the same recipe,
  seed and data this round would use; it is scored again here with this commit's binaries, like every model.
- **Everything else is R6's:** recipe, seed, validation, the evaluation pipeline, the gates, the decision rule,
  the holdout criteria. `long5` stays dev; `long7` replaces `long6` as the holdout.

## Disclosure

- `long5` (both halves) was v7 dev in R6, and `long`, `long5` and `long6` have been scored on both halves. R6's
  dev and holdout numbers above, including `ref`'s (long5 under `strong75`: 13 of 150 blocked, embedded 0.872
  against 0.888 alone; eval/data dev TPR at FPR ≤ 1% 0.9473), are known. `long5` is v8 **dev**; it is never
  used for training (the v8 builder's guard drops every row sharing a 50-token run with it).
- The eval/data hold-out slice is not fresh: R6 read it for C, `ref` and B (`v7_holdout.md`), so `ref`'s value
  (0.9618, CP95 low 0.9432 with R6's binaries) is known. It is read again only at the holdout stage below.
- `long7` was built and checked for overlap only (`bench_guard` against the v4-A, v6 and v7 training and
  validation rows and the v7 pool: 0 overlaps; 362 units excluded; no unit near-duplicates a quick, full, long,
  long5 or long6 document). Neither the 180 benign documents nor the 336 embedded and 48 stand-alone attack
  documents have been scored by any model or rule layer. The `long7` payloads are eval/ dev-half attack rows 96
  to 119 per language in build.py's seeded order, disjoint from `full` (0–31), R5 (32–71) and `long6` (72–95);
  as eval/data dev rows they are inside the aggregate G1 numbers of every report since v3.
- The v8 data uses no new score: the hosts are R6's v7 rows (mined by the released v6 in R6), the payloads are
  attack rows of `data/train.jsonl` (v5/v6 payload set A), and every row passed the guard of `build_v8.py check`
  (bench/long quick to long7, the R5, long6 and long7 attack documents, every eval/ and hold-out row; 0 of
  22,540 and 0 of 16,906 rows overlap).
- The RF-b74de2b9 timing files (`guardspec-data/v6/colab/gs-b74-g4b/out/timing-*`) concern `long6` and are not
  opened in R7.

## Data

### Training addition (`train/data/build_v8.py`, `sources_v8.yaml`, `stats_v8.json`, DATA_CARD "v8 data")

| file (`guardspec-data/v8/data`, not in git) | rows | SHA-256 | size |
|---|---|---|---|
| `v8_train.jsonl` (arm D) | 22,540 (11,270 `v8_benign` + 11,270 `v8_attack`) | `1305e50f756c9f3ad375518976953845ab2d3519a1ce2571998dc8177ea9320e` | 35.2 MB |
| `v8e_train.jsonl` (arm E) | 16,906 (5,636 + 11,270) | `7f51cdb409fa4af9121b30ddc8708e7aa1cac186d33f668fa7a614b433195550` | 27.3 MB |

Built with seed 20261113; two builds are byte-identical. Attack rows carry `spans` / `byte_spans`, so
`windows.label_windows` labels each gateway window (a host-only window of a straddle row is benign; 1,301
windows holding about half a payload are dropped).

### Dev: `long5` (both halves) and the R5 attack documents

As R6: 150 benign documents (75 at 100k, 75 at 200k tokens; `outputs.long5`) and the 554 embedded-attack
documents plus 80 controls of R5 (`bench/long/embed_long.py --eval-payloads 40 --eval-skip 32`, both splits).

### Holdout: `long7`

`bench/long/corpus.yaml` profile `long7`, committed in ea80631: 180 benign documents, 26.96M tokens, 45 per
language (English, Vietnamese) and size (100k, 200k), from sources no other profile and no v7 or v8 training
source uses (English Wikipedia file 00004, English Wikisource file 00004, Vietnamese Wikipedia row groups 216–255
of file 00003, U.S. Code titles 14/25/39/41/43/51/52/54, 78 further RFCs, the Istio documentation and blog,
Docker guides, containerd v2.0.0 Go code, synthetic genres with seed 20261115), `outputs.long7` =
`3123957ce5bef40da71d5cc18d57516af0f260b8fe677fe0c532f8c22329229d`. Every `long7` document is v8 holdout, whatever
its `split` field says.

Attack documents (`guardspec-data/v8/long7/attack/docs.jsonl`, not in git): `embed_long.py --eval-payloads 24
--eval-skip 96` on `long7` hosts of the same language, dev and holdout splits concatenated: 48 payloads, 48
controls (payloads alone) and 336 embedded documents (seven placements), SHA-256
`81bebe98e85a01af0f062dd911890d2b9d8535ba8dbec0e5fa48e4a657594ede`. No payload shares a 50-token run with a
training row (`bench_guard`).

## Arms

Same recipe for every arm: `train.py` as v6 arm A (window-level training, multilingual-e5-small at the pinned
revision, seed 20261105, 5 epochs, batch 32, lr 5e-5, the v3 oversampling of the realistic Vietnamese rows,
augmentation as in `config.yaml`), validation the v6 files (the v4-A build's `val`, `val_hard`,
`val_vi_variants`, `val_v3`, `val_v4`, plus `v6_val` and `val_v6`; never a hold-out) for every arm, so the epoch
is selected on the same validation as R6.

| arm | training data | Colab job |
|---|---|---|
| `ref` | v4-A training data + `v6_train` (v6 arm A on the L4): **R6's model `v7-ref`, reused, not retrained** | none |
| `D` | `ref` + `v8_train.jsonl` (`--v8-dir`) | `v8-D` |
| `E` | `ref` + `v8e_train.jsonl` (`--v8-dir --v8-file v8e_train.jsonl`) | `v8-E` |

Commands (the colab-gpu skill; `$DATA_DIR` holds what `run_arms_v8.sh stage <arm>` prepared):

```sh
cd train && python3 train.py --data-dir "$DATA_DIR/data-v4A" --v6-dir "$DATA_DIR/out-full" --v8-dir "$DATA_DIR/v8" \
    --seed 20261105 --run-dir "$OUT_DIR/D"
cd train && python3 train.py --data-dir "$DATA_DIR/data-v4A" --v6-dir "$DATA_DIR/out-full" --v8-dir "$DATA_DIR/v8" \
    --v8-file v8e_train.jsonl --seed 20261105 --run-dir "$OUT_DIR/E"
```

Training on one Colab L4 per job, one job at a time, about 5 compute units for the round (estimate below). The
v4-A build holds owner rows (`train.jsonl` 1,016, `val.jsonl` 124): R6's approval covered R6's jobs only, so
**no v8 job starts before the owner approves in chat** that these files go to Colab for `v8-D` and `v8-E`. Then
`--allow-owner-data` for those jobs only; only the files `train.py` reads are uploaded (`run_arms_v8.sh stage`,
which refuses a hold-out or probe file), never `user_holdout.jsonl` or a `val_*_holdout` file, and
`/content/job/<name>/data` is deleted before the VM stops. Each arm is exported to INT8 with `export.py`
(`--data-dir` v4-A, `--v6-dir`) and calibrated with `cmd/calibrate fit -write` on the validation files above.

Estimate (from R6 on the same L4: `ref` 52,373 windows in 32.5 min, B +12,591 long windows +9.3 min, about
0.037 compute units per training minute): D about 77,200 windows, 50 min, 1.9 units; E about 70,900 windows, 46
min, 1.7 units; 3.6 units together, 5 at most. A job heading past 2.5 units is stopped and reported.

## Evaluation pipeline (every number from ONNX INT8 on the laptop's CPU)

As R6, with this commit's binaries for every model (`ref` and the released v6 are scored again, not read
from R6's dumps, because the inference code changed after R6):

- Short path and full profile: `cmd/eval` and `cmd/benchlong -profile full -layers "l1;l1,l2" -l2cap on`
  (`run_arms_v8.sh gates`), with the rule set of this commit (the R5 `r5` rules).
- Long path: `cmd/benchlong -long on -layers none -l2pass off -dump` (the gateway's `ml.ScoreLong`: 256-token
  windows fused `l1,l2` with the model's own calibration and cap, code corroboration), rule set `r5`, and the R5
  document decisions recomputed from the dumps by `longdoc_v8.py` (`longdoc_v7.py`'s code): **`strong75`** is
  the evaluation decision, `base` is reported next to it; n0 = 30.

## Gates (dev only)

For `D`, `E` and `ref`, exactly R6's (`select_v7.gates_v7`): G1–G7 as v6 (`select_v6.gates_for`; eval/data,
codelog, embedded, val_v3, bench/long full dev), with v3b and L1 alone scored again by the same binaries; and

- **G8** `eval/data` dev TPR at FPR ≤ 1% (direct) not below the lower end of the two-sided 95%
  Clopper–Pearson interval of `ref`'s value (k = round(TPR × attacks)).
- **LD-TPR** long5: detection of the R5 embedded documents (seven placements, EN and VI, both halves pooled)
  under `strong75` ≥ detection of the same payloads alone − 0.05.
- **LD-REF** long5: blocked benign 100k + 200k documents under `strong75` fewer than `ref`'s.

Recorded, not gating: **LD-FPR** (the target on dev): blocked long5 documents ≤ floor(0.01 × 150) = 1;
`base` next to `strong75`; the released v6 on the same long5 documents with the same binaries; latency and
score pass as v6.

## Decision rule

Among `D` and `E`, the arms passing G1–G8, LD-TPR and LD-REF: the fewest blocked long5 benign documents under
`strong75`; tie: higher long5 embedded detection; tie: higher G1 (four decimals); tie: the order D, E. That arm
is **v8**. "Meets the target on dev" if it also meets LD-FPR. If no arm passes, there is no v8: the arm meeting
most of these gates (tie: the same keys) is a fallback candidate for the owner only; its `long7` numbers are
still scored once, for the record. `select_v8.py` writes `reports/v8_dev.json`; `reports/v8_dev.md` reports it.

## Holdout (once)

After `reports/v8_dev.{json,md}` is committed (`run_arms_v8.sh holdout` refuses to run before, and scores only
the models below): `long7` (benign and attack documents) is scored once on the long path with the chosen (or
fallback) arm, `ref`, and the released v6, and `longdoc_v8.py --stage holdout` reports `strong75` and `base`
for each, with two-sided Clopper–Pearson 95% intervals: blocked benign documents at 100k, at 200k and pooled,
per language; detection alone and embedded, per placement and pooled; and the eval/data hold-out slice (from
the dev-stage `cmd/eval` reports, read only now) for the chosen arm against `ref`.

**Met** means all of:

1. `strong75` blocked benign documents ≤ 1% at 100k and at 200k tokens on `long7` (90 documents per size, so
   0 blocked at each size);
2. `long7` embedded detection ≥ detection of the same payloads alone − 5 points (`strong75`, pooled);
3. eval/data hold-out TPR at FPR ≤ 1% not below the lower end of `ref`'s two-sided CP95 interval.

Gates and criteria are on INT8 ONNX on the CPU. Reported whatever the result; no parameter, arm or criterion
changes after that.

## Implementation commitment

Nothing is published, tagged, released or uploaded beyond the training jobs above: a chosen v8 is packaged under
`guardspec-data/v8/release` only, not added to `models/manifest.yaml`; switching the default stays the owner's
decision. The rule set and the long-path decision in the code are unchanged by R7.
