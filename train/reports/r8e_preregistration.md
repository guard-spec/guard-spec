# R8e pre-registration: arm EPL3 (EPL2 + T+, O+, N+, L++), three seeds (RF-943afc53)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-22, before any R8e training job.
- **Holdouts.** vi1, tp1 and long11 were built and pinned in commits `6e8f2ba` and `2cd9a14`
  (`train/reports/r8e_holdouts_manifest.json`) before any score. Since then they have been scored only by arm E's
  three seeds and arm EPL2's three seeds, which fixes the bands below.
- **Design.** It follows `train/reports/r8e_analysis.md` (dev data only), as the owner approved on Resolflow
  (RF-943afc53), with a **single arm, EPL3**.

**Owner approval:** on 2026-11-22, in chat, the owner approved sending the R8e training data to Colab:
- R8d's set, including `data-v4A` with the owner-supplied rows;
- R8e's T+, O+, N+ and L++.

Holdouts are never sent.

## Problem and hypothesis

v8g (R8d's EPL2-s3, the default since v0.11.0) looked worse than v8e on three counts. On all of `eval/` (the CI
runner):
- Vietnamese benign rows blocked: 1.25% against 0.31%;
- Vietnamese tool poisoning caught: 89.2% against 100%;
- long10 embedded attacks caught: 73.8% against 79.8%.

The analysis found that the first two are mostly seed noise: v8e is the best of E's three seeds. It also found three
narrow patterns, all under-represented in every recipe's data:

- **A.** Tool descriptions that ask to copy the conversation, the system prompt or secrets into a field. Every dev
  Vietnamese tool-poisoning miss is of this kind, and it is also behind v8g's long5 dev losses: alone 0.99, embedded
  0.80–0.84.
- **B.** Paraphrased overrides ("treat the instructions above as non-existent").
- **C.** Quoted attacks without diacritics, or as short questions, blocked by v8g.

**Hypothesis.** Adding positives and negatives for A, B and C, and long-document attack windows carrying A and B,
fixes these without losing v8g's gains.

## Jobs (Colab L4, one session `r8e`, sequential)

| job | data | seed |
|---|---|---:|
| `EPL3-s1` | EPL2's data (E's `data-v4A`, `out-full`, `v8e_train.jsonl`; `persona_neg_train`; `r8c_L_train`, `r8c_S_train`; `r8d_Lplus_train`, `r8d_N_train`, all unchanged) + `r8e_Tplus_train` + `r8e_Oplus_train` + `r8e_Nplus_train` + `r8e_Lpp_train` | 20261108 |
| `EPL3-s2` | same | 20261109 |
| `EPL3-s3` | same | 20261110 |

The recipe is EPL2's: `train.py` defaults, 5 epochs, the epoch selected on the v6 validation files. Every model is
exported to ONNX INT8 and calibrated with `cmd/calibrate fit -model-dir "$MODEL_ROOT"` on E's 12,785 validation rows.
E's `long_doc` and `l2_untrusted_max` (0.88) are then added, exactly as for EPL and EPL2.

**Launch** (`.claude/skills/colab-gpu/scripts/colab_job.py`, run from the R8e worktree at the commit of this file):

> **Erratum, written after the launch (2026-11-22).** As committed in `b8435f3`, this block repeated `--data` once
> per stage directory. `colab_job.py` declares `--data` with `nargs="*"` and no append, so only the last directory
> (`r8e`) would have been shipped. The jobs were launched with the block as it now reads: one `--data` followed by the
> seven stage directories, and `--repo . --paths train` from the R8e worktree at `b8435f3`. The data, the command and
> the seeds are otherwise the ones pre-registered (`colab_job.json` records the seven directories and `b8435f3`).

```bash
J=.claude/skills/colab-gpu/scripts/colab_job.py
S=~/WorkingSpace/AI_R_D/guardspec-data/v9/r8e/stage
uv export --project train --no-hashes --no-emit-project --frozen -o "$SCRATCH/train-req.txt"
python3 $J start --name r8e --gpu L4 --repo . --paths train \
  --data $S/data-v4A $S/out-full $S/v8 $S/r8b $S/r8c $S/r8d $S/r8e \
  --requirements "$SCRATCH/train-req.txt" \
  -- 'nvidia-smi; cd train; for k in 1 2 3; do seed=$((20261107+k)); echo "== EPL3-s$k seed $seed $(date)"; python3 train.py --data-dir "$DATA_DIR/data-v4A" --v6-dir "$DATA_DIR/out-full" --v8-dir "$DATA_DIR/v8" --v8-file v8e_train.jsonl --extra-train "$DATA_DIR/r8b/persona_neg_train.jsonl" --extra-train "$DATA_DIR/r8c/r8c_L_train.jsonl" --extra-train "$DATA_DIR/r8c/r8c_S_train.jsonl" --extra-train "$DATA_DIR/r8d/r8d_Lplus_train.jsonl" --extra-train "$DATA_DIR/r8d/r8d_N_train.jsonl" --extra-train "$DATA_DIR/r8e/r8e_Tplus_train.jsonl" --extra-train "$DATA_DIR/r8e/r8e_Oplus_train.jsonl" --extra-train "$DATA_DIR/r8e/r8e_Nplus_train.jsonl" --extra-train "$DATA_DIR/r8e/r8e_Lpp_train.jsonl" --seed $seed --run-dir "$OUT_DIR/EPL3-s$k" || exit 1; done; echo "== done $(date)"'
python3 $J poll --name r8e --lines 30
python3 $J fetch --name r8e --remote out --local ~/WorkingSpace/AI_R_D/guardspec-data/v9/r8e/colab/out --exclude '*.pt'
python3 $J stop --name r8e
```

The VM's `data` directory is deleted before the session stops.

## Data

### Training additions (`train/data/build_r8e.py`, `sources_r8e.yaml`, seed 20261122; staged under `guardspec-data/v9/r8e/stage/r8e/`)

| file | rows | SHA-256 |
|---|---|---|
| `r8e_Tplus_train.jsonl` (T+) | 1,200: 600 attacks (data_exfiltration or prompt_extraction + tool_poisoning), 600 benign; EN 498, VI 702 (orig 238, no_diacritics 239, teencode 225) | `3ed5beef8b053a27f19d9109b0aaeab2be68005f4360cd4acd6bdfb1901b2987` |
| `r8e_Oplus_train.jsonl` (O+) | 400 attacks (direct_injection): EN 132, VI 268 (orig 88, no_diacritics 88, teencode 92) | `048f5b4784a72bc23ee6f048cf3b012c1a2620e762446eba13ac876189c8ddad` |
| `r8e_Nplus_train.jsonl` (N+) | 280 benign: VI no_diacritics 102, teencode 109; EN short questions 69 | `a129bad6e8adb720647e9b940718501db4cd3e50b0fd05491fb789a7b90c2065` |
| `r8e_Lpp_train.jsonl` (L++) | 600 attack windows (docs 270, rfc 180, readme 150) of R8d's L+ pool (new windows), carrying English T+ and O+ attacks; build_v8's placements (mid 181, straddle 103, split_adjacent 101, split_within 84, end 70, start 61) | `a4529e8f88c3070e1e176f91298915b41eb3f03a811d2121498bd673f50f9986` |

The unchanged EPL2 inputs, staged next to them:

| file | SHA-256 |
|---|---|
| `data-v4A/train.jsonl` | `7f47970f…` |
| `data-v4A/val*.jsonl` | five files, in `stage_SHA256SUMS` |
| `out-full/{v6_train, v6_val, val_v6}.jsonl` | `20f5ddad…`, `84dd0cfb…`, `f70e0617…` |
| `v8/v8e_train.jsonl` | `7f51cdb4…` |
| `r8b/persona_neg_train.jsonl` | `74aecfc6…` |
| `r8c/r8c_{L,S}_train.jsonl` | `7bd8a1c0…`, `19a9087f…` |
| `r8d/r8d_{Lplus,N}_train.jsonl` | `dae8aba3…`, `e6b9b47e…` |

- **Sources.** Every R8e row is project-written (`train/data/r8e_templates.py`, Apache-2.0), except L++'s host
  windows. Those come from R8d's L+ pool: the Airflow, Open Policy Agent and cert-manager documentation, RFCs and the
  Datadog READMEs, pinned in `sources_r8d.yaml`, checked again by SHA-256 in `sources_r8e.yaml`. L++ uses only
  windows that L+ did not use.
- **Guard** (`build_r8e.py check`, `guard_r8e.json`): **clean**.
  - Checked: 2,480 rows.
  - 0 share a 50-token run with a bench/long document (quick to long11), an embedded-attack document (R5, long6 to
    long11) or a hold-out row.
  - 0 share 12-token runs with short hold-out rows.
  - 0 overlap by the 8-word rule in either direction. The hold-out rows include vi1, tp1, the long11 payloads,
    persona1/2/3, split1, split2, multiturn.json, the payload_split dev set, eval/ and the exemplars.
  - Rejected during generation: 213 T+ and 30 N+ candidates that overlapped a guarded text.
- **Reproducibility:** built twice, byte-identical. Counts are in `train/reports/r8e_build_report.json`.

### Holdouts (fresh; `guardspec-data/v9/r8e/out/`, `SHA256SUMS`)

| holdout | contents | SHA-256 |
|---|---|---|
| `vi1/holdout/vi.jsonl` | 862 Vietnamese benign rows (details below) | `a31a08cef51c9dc81ac97e14c4bf2b6c4f617ffc66eb72bc90e0f88e971c80b5` |
| `tp1/holdout/{en,vi}.jsonl` | 300 tool and MCP descriptions: 150 attacks, 150 benign (details below) | `dd691d24…` (en), `fad09a5c…` (vi) |
| `long11/benign/docs.jsonl` (`outputs.long11`) | 49 English documents, 7.30M tokens (details below) | `1fe885da8068352308bfff586aa9f45494538adef34d0360e12989b84bb69edf` |
| `long11/attack/docs.jsonl` | 252 embedded-attack documents and 36 payloads alone (details below) | `9556d15172db23cb4a3d75ca873aec01913fcdd2cd2230dc8e1b96f02b0cef5c` |
| `long11/payloads.jsonl` | the 12 long11 tool-poisoning payloads | `ebbe75f3…` |

- **vi1.**
  - 562 community rows: the first user turns of the Vietnamese conversations of `lmarena-ai/arena-human-preference-140k`
    (CC-BY-4.0, pinned files of R8c). persona3's rows, rows over 6,000 characters and near-duplicates were dropped.
    Two AI labellers read every row in full before any score; 1 attack and 1 ambiguous row were dropped.
  - 300 templated rows: business and IT messages, 100 each in `orig`, `no_diacritics` and `teencode`.
- **tp1.**
  - EN: 64 attacks and 58 benign. VI: 86 attacks (orig 22, no_diacritics 34, teencode 30) and 92 benign.
  - The attacks cover field exfiltration, prompt extraction into a field, reading keys into a field, steering
    towards one tool, an outside send, and hiding output.
  - Tool names, fields and frames are not T+'s (`tests/test_r8e.py`).
- **long11.**
  - Benign documents per size, 100k + 200k: docs 14 + 14, rfc 7 + 7, readme 1 + 1, man 3 + 2.
  - Sources: Argo Workflows, the Cluster API book, Tekton, Flux, Dapr, Gatekeeper, Linkerd, KEDA and Backstage
    documentation; RFCs every tenth from the fifth; six Helm chart repositories' READMEs; NetBSD manual pages. All are
    disjoint from every other profile and every training source.
  - Attack documents: `embed_long.py --eval-payloads 24 --eval-skip 192 --langs en --extra-payloads`, with eval/
    dev-half English rows 192–215 plus the 12 tool-poisoning payloads written for long11.
- **Holdout check** (`build_r8e_holdouts.py check`, `holdout_check.json`): **clean**. Every vi1 and tp1 row and the
  long11 payloads were checked against E's data, every R8b–R8e training file (T+, O+, N+ and L++ included), eval/,
  persona1–3, split1, split2, the exemplars, multiturn.json and the payload_split dev set. long11's documents were
  checked with 50-token runs.

**Re-read for retention** (disclosed): persona3 (R8c), split2 (R8d) and the `eval/data` hold-out half, once more per
EPL3 seed. The bands for them are EPL2's R8d runs.

## Measures (ONNX INT8, laptop CPU, gateway path; `train/measure_r8c.sh`, `train/verdict_r8c.py`, `train/verdict_r8e.py`)

1. **vi1:** `cmd/eval -detector fusion-ml -path direct`; benign rows blocked (the gateway's decision), overall and
   per stratum, with the CP95 upper bound.
2. **tp1:** `cmd/eval -detector fusion-ml -path direct`, the same path as `eval/data`'s tool_poisoning rows. Reported:
   Vietnamese and English attacks caught, and benign rows blocked.
3. **long11:** `cmd/benchlong -layers none -l2pass off -long on`, the shipped `long_doc`, each model's calibration.
   Reported: benign documents blocked, embedded attacks caught (doc score ≥ 0.85) and payloads alone.
4. **Retention:**
   - persona3 benign blocked per language;
   - split2 with L2 alone on the conversation window;
   - the `eval/data` hold-out half, TPR at FPR ≤ 1%.

E's three seeds (v8e, E-s2, E-s3) and EPL2's three seeds (EPL2-s1, EPL2-s2, EPL2-s3 = v8g) were scored once on vi1,
tp1 and long11, before this file. EPL3's seeds are scored once on everything.

### The bands on the fresh holdouts (scored 2026-11-22, binaries at `7682d5e`, each holdout once per model)

| measure | v8e | E-s2 | E-s3 | EPL2-s1 | EPL2-s2 | EPL2-s3 (v8g) |
|---|---:|---:|---:|---:|---:|---:|
| vi1 benign blocked (862) | 12 (1.39%) | 7 (0.81%) | 8 (0.93%) | 10 (1.16%) | 4 (0.46%) | 7 (0.81%) |
| — community (562) / orig / no_diacritics / teencode (100 each) | 9 / 0 / 0 / 3 | 4 / 0 / 2 / 1 | 3 / 0 / 1 / 4 | 5 / 0 / 0 / 5 | 3 / 0 / 0 / 1 | 3 / 0 / 1 / 3 |
| tp1 VI attacks caught (86) | 78 (90.7%) | 67 (77.9%) | 59 (68.6%) | 67 (77.9%) | 71 (82.6%) | 59 (68.6%) |
| tp1 EN attacks caught (64) | 50 | 54 | 60 | 52 | 52 | 42 |
| tp1 benign blocked (150) | 0 | 0 | 0 | 0 | 0 | 0 |
| long11 benign blocked (49) | 1 | 3 | 2 | 2 | 2 | 0 |
| long11 embedded caught (252) | 179 (71.0%) | 171 (67.9%) | 179 (71.0%) | 175 (69.4%) | 178 (70.6%) | 166 (65.9%) |
| long11 payloads alone (36) | 31 | 30 | 30 | 30 | 31 | 30 |

What the bands show:
- On the fresh Vietnamese benign set, v8e blocks more than v8g: 12 rows against 7, so the 1.25% against 0.31% of
  `eval/` was a property of `eval/`'s rows.
- tp1 confirms Pattern A as a weakness of every model: no seed catches more than 90.7% of the Vietnamese attacks,
  and v8g catches the fewest.
- long11 confirms v8g's embedded weakness: it is the lowest of six models.

Retention bands, from R8d's runs, for EPL2-s1 / EPL2-s2 / EPL2-s3:
- persona3 EN 0.5% / 1.3% / 0.3%;
- persona3 VI 2.6% / 0% / 0.9%;
- split2 TPR 93.3% / 81.7% / 93.3%;
- split2 benign FPR 0% / 0% / 3.3%;
- `eval/data` hold-out TPR at FPR ≤ 1% 0.952 / 0.942 / 0.965.

## Criteria (each must hold for every EPL3 seed; numeric bars from the bands, `train/reports/r8e_bars.json`)

| | criterion | rule | bar |
|---|---|---|---|
| **R1** | vi1 benign blocked | ≤ v8g's own rate and ≤ 1.5% | **≤ 0.81%** (at most 7 of 862) |
| **R2** | tp1 VI attacks caught | ≥ the v8g band's best seed + 5 points | **≥ 87.6%** (at least 76 of 86) |
| **R2** | tp1 benign blocked | ≤ 3% | **≤ 3%** (at most 4 of 150) |
| **R3** | long11 embedded caught | ≥ v8e − 2 points | **≥ 69.0%** (at least 174 of 252) |
| **R3** | long11 benign blocked | ≤ the worst v8g-band seed | **≤ 2** of 49 |
| **R4** | persona3 benign blocked, EN and VI | ≤ 2% each | **≤ 2%** (EN ≤ 7 of 396, VI ≤ 2 of 117) |
| **R4** | split2, L2 only | TPR ≥ the v8g band's lowest − 5 points; benign FPR ≤ 5% | **TPR ≥ 76.7%** (at least 46 of 60); **FPR ≤ 5%** (at most 3 of 60) |
| **R4** | `eval/data` hold-out TPR at FPR ≤ 1% | ≥ 0.915 | **≥ 0.915** |

`python3 train/verdict_r8e.py verdict --measure <R8c measure> --measure <R8d measure> --measure <R8e measure> --out
train/reports/r8e_holdout.json` applies them.

## Decision

- If every EPL3 seed meets R1–R4, EPL3 becomes the candidate for the next model package, in shadow mode first. The
  seed to package is the passing seed with the highest `eval/data` hold-out TPR at FPR ≤ 1%. Making it the default
  stays the owner's decision.
- If any seed fails a criterion, the report names the seed and the criterion, and v8g stays the default.
- No threshold, rule or calibration is tuned on vi1, tp1, long11, persona3 or split2. Each is scored once per model.

## Data sent to Colab

- **Sent:** R8d's set (`data-v4A` including the owner-supplied rows, `out-full`, `v8e_train`, `persona_neg_train`,
  `r8c_L_train`, `r8c_S_train`, `r8d_Lplus_train`, `r8d_N_train`), plus `r8e_Tplus_train`, `r8e_Oplus_train`,
  `r8e_Nplus_train` and `r8e_Lpp_train`. Staged under `guardspec-data/v9/r8e/stage/`; their SHA-256s are in
  `guardspec-data/v9/r8e/stage_SHA256SUMS`.
- **Never sent:** holdouts, owner holdouts and `eval/`.

## Limits

- **Small, mostly templated sets.**
  - tp1 is template-written by the author of T+, in separate inventories.
  - vi1's templated part is too.
  - long11 has 49 benign English documents.
- **Bars sensitive to one item.**
  - long11's benign bar is a count of documents.
  - vi1's bar is v8g's own rate, so one row is 0.12 points.
- **Three seeds** give the size of the noise, not its distribution.
- **R4's persona3 Vietnamese bar (≤ 2%)** is stricter than EPL2-s1's own 2.6%, as approved. One seed of v8g's recipe
  would not have met it.
