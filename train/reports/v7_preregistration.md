# v7 pre-registration: benign long text in training, long5 as dev, long6 as the holdout (RF-895d3533, R6)

Written on 2026-11-12, before any v7 or v6-reference training run, before any `long6` document was scored by
any model or rule layer, and before the v7 training data was scored by anything but v6 (the mining run
below). `train/select_v7.py` and `train/longdoc_v7.py` implement every definition here; their constants are the
values below. The `long6` corpus (`bench/long/corpus.yaml`, profile `long6`, pinned in `outputs.long6`) and its
embedded-attack documents were committed before this file.

## Problem and target

R5 (`r5_preregistration.md`, `r5_holdout.md`) left the long path at 5 of 76 benign holdout documents of 100k
and 200k tokens blocked (6.6%) with the `r5` rules and the `strong75` decision, 11 of 76 for v6 as it is. The
blocking windows are strong rules on benign text that L2 also scores high: role-play and "no restrictions"
wording in fiction, secrets and download commands in technical documentation, a send verb with an address in
RFC-like text. About 2.4 × 10⁻⁴ per window, some 20 times the 10⁻⁵ that 1% at 500 to 1,050 windows needs.
The owner chose to retrain the classifier with benign long text (v7).

Target (todo R6-3): on the long path with the R5 evaluation pipeline (below), blocked benign documents at most
1% at 100k and at 200k tokens; detection of attacks embedded in long documents at least the stand-alone
detection of the same payloads minus 5 points; `eval/data` not below v6.

## Disclosure

- `long` (R2b, R3) and `long5` (R5) have been scored on both halves. For R6 I read, on both halves of the R5
  `long5` dumps (window scores, no text), which benign documents the R5 decisions block and the calibrated L2
  of their blocking windows (docs-en, prose-en, prose-vi, wiki-vi and one legal-vi document with L2 0.002), and
  the lead's description of the blocking text quoted above. `long5` is v7 **dev** from now on (both halves);
  it is never used for training or mining.
- `long6` was built and checked for overlap only (`train/data/bench_guard.py` shingles against training data,
  R5's near-duplicate rule against the earlier profiles); no `long6` document or `long6` attack document has
  been scored by a model or a rule layer. The `long6` payloads are eval/ dev-half attack rows that no bench
  document used before (below); as eval/data dev rows they are inside the aggregate G1 numbers of every
  report since v3.
- The v7 training data is mined with the released v6 (INT8, laptop CPU) on the training pool only.

## Data

### v7 training addition (`train/data/sources_v7.yaml`, `train/data/build_v7.py`)

- Sources (all public domain or under a licence that allows this use, pinned like bench/long; no owner data):
  English Wikipedia (another file of the 2023-11-01 dump), English Wikisource (another file: books, stories,
  plays), U.S. Code titles 8, 19, 28, 46, 50, 60 RFCs no bench profile uses (mail, FTP, SNMP, RADIUS, NNTP,
  NFS, EPP, OAuth, SCIM, security.txt, ...), Kubernetes `pkg/proxy` and `pkg/volume` Go code (v1.31.0,
  licence comment stripped), the Docker Engine, Build, Docker Hub and Security manuals, the Prometheus
  documentation (v2.54.1); Vietnamese Wikipedia (another file), the Vietnamese Wikisource prose units and the
  Vietnamese Kubernetes and React documentation units no bench profile reads; and project-written generated
  passages in the three R5 genres (role-play fiction, secrets and download commands, RFC-like send-to-address),
  160 per genre and language, seed 20261114.
- Guard (stage `pool`): every unit sharing a run of 50 classifier tokens with a document of the bench/long
  profiles quick, full, long, long5 and long6, with an R5 or `long6` embedded-attack document, or with a
  hold-out row (every eval/ set, the repository's `val_*_holdout`, the v6 hold-out stage's splits including the
  owner hold-outs, read locally) is dropped; hold-out rows under 50 tokens are checked with 12-token runs. This
  subsumes R5's near-duplicate rule (20% of the 50-token shingles), which therefore drops nothing further.
- Mining (stage `rows`): the pool (genre caps in `build_v7.py`, documents of about 30k tokens) is scored once
  by the released v6 on the long path (`cmd/benchlong -long on -dump`, INT8, CPU, current rules). A window is a
  **hard negative** (`kind: v7_hardneg`) when its fused long-path score is at least 0.5 or its calibrated L2 at
  least 0.3, at most 1,500 per language (highest first). A seeded random sample of the other windows per genre
  and language (`sample.windows` in the yaml: 6,000 English and 3,900 Vietnamese at most) is `v7_long`; the
  generated passages are `v7_gen`. Every row is benign, one gateway window (the window's text in the sanitized
  document), English or Vietnamese.
- Check (stage `check`): `bench_guard` of the final rows against the same documents and hold-outs; 0 rows may
  share a 50-token run. The row counts, `stats_v7.json` and the SHA-256 of `v7_train.jsonl` are recorded under
  "Recorded before the first v7 arm" below, before the first v7 training job.

### Dev: `long5` (both halves) and the R5 attack documents

150 benign documents (75 at 100k, 75 at 200k tokens; `outputs.long5`) and the 554 embedded-attack documents
plus 80 controls of R5 (`bench/long/embed_long.py --eval-payloads 40 --eval-skip 32`, both splits).

### Holdout: `long6`

`bench/long/corpus.yaml` profile `long6`, committed in bb7af74 before this file and before any v7 or
reference training run: 90 benign documents, 13.38M tokens (English 26 at 100k and 24 at 200k: Wikipedia,
U.S. Code titles 21/22/23/31/47, Prometheus Go code, Kubernetes setup/tutorials/contribute and Docker
Compose/Desktop/Scout/Hardened Images documentation, English Wikisource, 46 further RFCs, six synthetic genres;
Vietnamese 20 and 20: Wikipedia and six synthetic genres; the Vietnamese laws left after `long5` dropped out
after exclusion), `outputs.long6` = `b87e52e7d6b8d8526c12e379dc5ed868e29a7d9968ae3733b7b9ef913afe94b8`. No unit
shares a 50-token run with a v6 or v4-A training or validation row (282 units excluded, `exclude.json`;
`bench_guard` on the built file: 0 of 64,174 rows), and no unit near-duplicates (20% of its shingles) a quick,
full, long or long5 document. Every `long6` document is v7 holdout, whatever its `split` field says.

Attack documents: `bench/long/embed_long.py --eval-payloads 24 --eval-skip 72 --long <long6> --split dev` and
`--split holdout`, concatenated: 48 payloads (eval/ dev-half attack rows 72 to 95 of each language in
build.py's seeded order; the `full` profile took rows 0 to 31, R5 rows 32 to 71), 48 controls and 336 embedded
documents (seven placements) in `long6` hosts of the same language, 49.5M tokens, SHA-256
`39c95931345f9368a7f827180c52fe7a312bf3d5d4a588ed00f4b066f091ba66`. No payload shares a 50-token run with a
v6 or v4-A training row (`bench_guard`). The v7 training builder drops every unit that shares a 50-token run
with a `long6` document or a `long6` attack document.

## Arms

Same recipe for every arm: `train.py` as v6 arm A (window-level training, multilingual-e5-small at the pinned
revision, seed 20261105, 5 epochs, batch 32, lr 5e-5, the v3 oversampling of the realistic Vietnamese rows,
augmentation as in `config.yaml`), validation the v6 files (the v4-A build's `val`, `val_hard`,
`val_vi_variants`, `val_v3`, `val_v4`, plus `v6_val` and `val_v6`; never a hold-out) for every arm, so the
epoch is selected on the same validation. Training on one Colab L4 per job (colab-gpu skill), one job at a time;
the MPS-trained v6 release is not the reference.

| arm | training data |
|---|---|
| `ref` | v4-A training data + `v6_train` (v6 arm A, retrained on the L4: the GPU reference) |
| `B` | `ref` + `v7_train` (every v7 row once) |
| `C` | `B` with the mined hard negatives (`v7_hardneg`) three times per epoch |

The owner approved on 2026-11-12 (chat) that the owner rows of the v4-A build (`train.jsonl` 1,016,
`val.jsonl` 124) go to Colab for these jobs only: `--allow-owner-data` for them, only the files `train.py`
reads are uploaded (`run_arms_v7.sh stage`), never `user_holdout.jsonl` or a `val_*_holdout` file, and
`/content/job/<name>/data` is deleted before the VM stops. Each arm is exported to INT8 with `export.py`
(`--data-dir` v4-A, `--v6-dir`) and calibrated with `cmd/calibrate fit -write` on the validation files above.

## Evaluation pipeline (every number from ONNX INT8 on the laptop's CPU)

- Short path and full profile: `cmd/eval` and `cmd/benchlong -profile full -layers "l1;l1,l2" -l2cap on`, as
  the v6 gates (`run_arms_v7.sh gates`), with the rule set of this commit (the R5 `r5` rules).
- Long path: `cmd/benchlong -long on -layers none -l2pass off -dump` (the gateway's `ml.ScoreLong`: 256-token
  windows fused `l1,l2` with the model's own calibration and cap, code corroboration), rule set `r5`, and the
  R5 document decisions recomputed from the dumps by `longdoc_v7.py`: **`strong75`** (a window over 0.85 blocks
  only when L1 corroborates it at the calibrated value of a raw rule weight 0.75, and an L1 floor counts only
  when calibrated L2 is at least 0.5) is the evaluation decision, `base` (today's) is reported next to it.
  Texts of at most n0 = 30 windows (the R5 dev value, fixed here) keep `base`. The fusion of a window without
  its floor uses the model's own `logreg["l1,l2"]` and `l2_untrusted_max`.

## Gates (dev only)

For every arm and for `ref`: G1–G7 exactly as v6 (`select_v6.gates_for`; `train/MODEL_CARD.md`, v6, "Decision
rule": eval/data, codelog, embedded, val_v3, bench/long full dev), with v3b and L1 alone scored again by the same
binaries; and

- **G8** `eval/data` dev TPR at FPR ≤ 1% (direct) not below the lower end of the two-sided 95%
  Clopper–Pearson interval of `ref`'s value (k = round(TPR × attacks)).
- **LD-TPR** long5: detection of the R5 embedded documents (seven placements, EN and VI, both halves pooled)
  under `strong75` ≥ detection of the same payloads alone − 0.05.
- **LD-REF** long5: blocked benign 100k + 200k documents under `strong75` fewer than `ref`'s.

Recorded, not gating: **LD-FPR** (the target on dev): blocked long5 documents ≤ floor(0.01 × 150) = 1, per
size too; `base` next to `strong75`; the released v6 (MPS) on the same long5 dumps of R5 (same rules and
pipeline); latency and score pass as v6.

## Decision rule

Among `B` and `C`, the arms passing G1–G8, LD-TPR and LD-REF: the fewest blocked long5 benign documents under
`strong75`; tie: higher long5 embedded detection; tie: higher G1 (four decimals); tie: the order B, C. That arm
is **v7**. "Meets the target on dev" if it also meets LD-FPR. If no arm passes, there is no v7: the arm meeting
most of these gates (tie: the same keys) is a fallback candidate for the owner only; its `long6` numbers are
still scored once, for the record.

## Holdout (once)

After `reports/v7_dev.{json,md}` is committed: `long6` (benign and attack documents) is scored once on the long
path with the chosen (or fallback) arm, `ref`, and the released v6 (MPS), and `longdoc_v7.py --stage holdout`
reports `strong75` and `base` for each, with two-sided Clopper–Pearson 95% intervals: blocked benign documents
at 100k, at 200k and pooled, per language; detection alone and embedded, per variant and pooled; and the
eval/data hold-out slice (from the dev-stage `cmd/eval` reports, read only now) for the chosen arm against
`ref`. **Met** means: at 100k and at 200k, blocked benign ≤ 1% of the documents; embedded detection ≥ alone − 5
points; eval/data hold-out TPR at FPR ≤ 1% not below `ref`'s CP95 lower end. Reported whatever the result; no
parameter, arm or criterion changes after that.

## Implementation commitment

Nothing is published, tagged, released or uploaded: a chosen v7 is packaged under
`guardspec-data/v7/release` only, not added to `models/manifest.yaml`; switching the default stays the owner's
decision. The rule set and the long-path decision in the code are unchanged by R6.

## Recorded before the first v7 arm (2026-11-12)

- **Code change after c21d7d3, before any v7 row was written:** the first `pool` run dropped whole units on any
  hit (97 of the 112 RFC units shared the RFC boilerplate with `long` documents; Kubernetes files shared code
  with the long5 kubelet). `build_v7.py` now keeps the paragraphs of such a unit that share no run with the
  index (when they are at least 30% of it and clean together) and drops the rest; the final `check` stage is
  unchanged and decides. No score was read in between.
- **Pool** (`pool/docs.jsonl` SHA-256 `d7c22598e5c9033d06064189c2fad63c4f292f78dea341492b68bbf83ff7c282`): 475
  documents, 15.49M tokens (EN wiki 1.67M, prose 4.00M, docs 1.00M, RFC 0.81M, legal 1.50M, code 1.28M; VI wiki
  5.00M, prose 0.19M, docs 0.04M). Guard index: 201.6M shingles of 1,626 bench/long and attack documents and
  15,710 hold-out rows (6,653 shorter rows on 12-token runs); units dropped / trimmed per source in
  `pool_report.json` (U.S. Code 365 / 511, RFC 46 / 51, Kubernetes code 2 / 85, VI Wikipedia 17 / 90, ...).
- **Mining** (v6 release, INT8, M3 Max CPU, `cmd/benchlong -long on`, 16 min): windows with fused ≥ 0.5 or L2 ≥
  0.3: 440 English (prose 277, docs 67, RFC 54, legal 18, code 13, wiki 11) and 279 Vietnamese (wiki 193, docs
  72, prose 14), all kept (under the cap).
- **`v7_train.jsonl`** SHA-256 `87bbf5b95e5122f36f419fdf1bd83a0f6566466b5c46c4225d0cdf523b9754ab`: 11,270 rows,
  all benign: `v7_hardneg` 719 (EN 440, VI 279), `v7_long` 9,591 (EN 6,000: wiki 900, prose 1,500, docs 1,500,
  RFC 1,000, legal 500, code 600; VI 3,591: wiki 2,600, prose 900, docs 91, all there was), `v7_gen` 960.
  `check`: 0 of 11,270 rows share a 50-token run with any bench/long or attack document or hold-out row, 0
  share a 12-token run with a shorter hold-out row (`guard_v7.json`).
- **GPU reference trained** before this record (it does not read v7 data): job `v7-ref`, Colab L4 (driver
  580.82.07, CUDA 13.0), torch 2.13.0+cu130, transformers 5.10.2, Python 3.13.16 (the project pins 3.12),
  commit c21d7d3, seed 20261105, best epoch 5 of 5 (validation loss 0.0241; MPS v6 arm A 0.0232), 32.5 min of
  training, 1.45 compute units (399.96 → 398.51); the owner rows of the v4-A build were uploaded under the
  owner's approval of 2026-11-12, `/content/job/v7-ref/data` deleted before the VM stopped.

## Holdout exposure recorded before any long6 scoring (2026-11-12)

Reported by the lead, recorded before any model of R6 scored a `long6` document:

- The RF-b74de2b9 GPU timing job on Colab (session `gs-b74-g4b`, 2026-11-12 07:05 to 07:15 UTC, and the earlier
  lost run `gs-b74-g4`) used one `long6` benign document, `long6-wiki-en-200000-2`, as its 200k-token timing input.
  The model was the released v6 converted to FP16 on CUDA with its `fp16` calibration, not a v7 arm or `ref`.
- Its output files (`guardspec-data/v6/colab/gs-b74-g4b/out/timing-b*-r*.json`) hold per-run block counts. The lead
  saw only aggregate counts over the three timing documents together in one of them, never tied to this
  document, and nobody looked at per-document decisions. Those files are not opened for R6.
- **Decision, taken now and only because of the exposure:** `long6-wiki-en-200000-2` is left out of the `long6`
  benign holdout for every model scored (the chosen arm, `ref`, the released v6). The benign holdout is **89
  documents** (English 26 at 100k and 23 at 200k, Vietnamese 20 and 20): `guardspec-data/v7/long6/corpus-89/docs.jsonl`,
  SHA-256 `aefed525b4d01cba767c1dde8d6a88c23ad6497b7890a261a95f8b45bcd2b168`, the pinned `outputs.long6` file
  without that line. `run_arms_v7.sh holdout` is run with `GUARD_LONG6=guardspec-data/v7/long6-89` (its `corpus`
  is the 89-document file, its `attack` the unchanged attack documents).
- The attack documents are unchanged (the instruction covers the benign holdout): 3 of the 336 embedded
  documents use this document as their host; their scores were never seen either.
