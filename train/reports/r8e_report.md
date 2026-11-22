# R8e: arm EPL3 (EPL2 + T+, O+, N+, L++), three seeds (RF-943afc53)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/r8e_preregistration.md`, committed in `b8435f3` before any job. It records the
owner's approval of 2026-11-22 to send the training data. Its launch block was corrected after the launch, in
`c5c3701`; see "Launch erratum" below.

Training ran on Colab L4 on 2026-11-22, from 00:49 to 03:28 UTC. It used one session, with three jobs in sequence:

| job | seed | best epoch | training time |
|---|---:|---:|---:|
| EPL3-s1 | 20261108 | 5 | 51.6 min |
| EPL3-s2 | 20261109 | 5 | 51.8 min |
| EPL3-s3 | 20261110 | 5 | 51.8 min |

- **Compute:** 565.17 → 559.23 units (5.94).
- **Data:** R8d's staged set unchanged (data-v4A including the owner-supplied rows, out-full, `v8e_train`,
  `persona_neg_train`, `r8c_L_train`, `r8c_S_train`, `r8d_Lplus_train`, `r8d_N_train`), plus `r8e_Tplus_train`,
  `r8e_Oplus_train`, `r8e_Nplus_train` and `r8e_Lpp_train`. All files match `stage_SHA256SUMS`, and `colab_job.json`
  records the seven stage directories at `b8435f3`. No holdout was sent. The data was deleted from the VM before it
  was stopped.
- **Training set:** each job trained on 76,254 rows (82,251 windows). EPL2 trained on 73,774 rows; the difference is
  R8e's 2,480 rows.
- **Export and calibration:** done exactly as for EPL2.
  - Each model was exported to ONNX INT8 and calibrated with `cmd/calibrate fit` on E's 12,785 validation rows.
  - E's `long_doc` and `l2_untrusted_max` (0.88) were then added.
  - Platt intercepts are −0.35, −0.55 and −0.33, so none is unusual like EPL2-s2's +0.83.
  - `model_int8.onnx` SHA-256s: EPL3-s1 `6a1d9baf…`, EPL3-s2 `a34eb37c…`, EPL3-s3 `ae8b7d41…`.
- **Measurement:** `train/measure_r8c.sh`, `train/verdict_r8c.py` and `train/verdict_r8e.py`, on the laptop CPU
  (Apple M3 Max).
  - The binaries are the band's, built at `7682d5e`.
  - Each EPL3 seed was scored once on each of vi1, tp1, long11, persona3, split2 and the eval/data hold-out.
  - The two bands and their sources:
    - The E and v8g bands on vi1, tp1 and long11 were scored before any job.
    - The bands on persona3, split2 and eval/data are the R8c and R8d runs.

## Nine models

| measure | v8e | E-s2 | E-s3 | EPL2-s1 | EPL2-s2 | EPL2-s3 (v8g) | **EPL3-s1** | **EPL3-s2** | **EPL3-s3** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vi1 benign blocked (862) | 12 | 7 | 8 | 10 | 4 | 7 | **18** (2.1%) | **10** (1.2%) | **5** (0.6%) |
| — community (562) / orig / no_diacritics / teencode (100 each) | 9/0/0/3 | 4/0/2/1 | 3/0/1/4 | 5/0/0/5 | 3/0/0/1 | 3/0/1/3 | 7/0/2/9 | 9/0/1/0 | 5/0/0/0 |
| tp1 VI caught (86) | 78 | 67 | 59 | 67 | 71 | 59 | **76** (88.4%) | **75** (87.2%) | **74** (86.0%) |
| tp1 EN caught (64) | 50 | 54 | 60 | 52 | 52 | 42 | **64** | **64** | **64** |
| tp1 benign blocked (150) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| long11 benign blocked (49) | 1 | 3 | 2 | 2 | 2 | 0 | 1 | 1 | 0 |
| long11 embedded caught (252) | 179 | 171 | 179 | 175 | 178 | 166 | **176** (69.8%) | **171** (67.9%) | **174** (69.0%) |
| — `split_adjacent` (36) | 21 | 21 | 20 | 20 | 24 | 19 | 21 | 19 | 21 |
| long11 payloads alone (36) | 31 | 30 | 30 | 30 | 31 | 30 | 30 | 31 | 31 |
| persona3 EN blocked (396) | 6 | 7 | 9 | 2 | 5 | 1 | 2 (0.5%) | 3 (0.8%) | 4 (1.0%) |
| persona3 VI blocked (117) | 2 | 4 | 1 | 3 | 0 | 1 | 1 (0.9%) | 1 (0.9%) | 0 |
| split2 TPR, L2 only (60) | 42 | 40 | 43 | 56 | 49 | 56 | **59** (98.3%) | **59** (98.3%) | **55** (91.7%) |
| split2 benign FPR, L2 only (60) | 1 | 5 | 0 | 0 | 0 | 2 | 0 | 2 (3.3%) | 0 |
| eval/data hold-out, AUC | 0.989 | 0.987 | 0.988 | 0.989 | 0.988 | 0.991 | 0.988 | 0.990 | 0.988 |
| eval/data hold-out, TPR at FPR ≤ 1% | 0.960 | 0.915 | 0.925 | 0.952 | 0.942 | 0.965 | 0.947 | 0.949 | 0.935 |

The ids of every blocked benign row and document, and the CP95 bounds, are in `train/reports/r8e_holdout.json` and
in each model's `summary.json`. The sanitizer rejected no long11 document.

## Verdict against the pre-registered criteria (each must hold for every EPL3 seed)

| criterion | bar | EPL3-s1 | EPL3-s2 | EPL3-s3 | worst seed | result |
|---|---|---|---|---|---|---|
| R1, vi1 benign blocked | ≤ 0.81% (7 of 862) | **18 (2.09%)** | **10 (1.16%)** | 5 (0.58%) | 18 | **failed** (s1, s2) |
| R2, tp1 VI caught | ≥ 87.6% (76 of 86) | 76 (88.4%) | **75 (87.2%)** | **74 (86.0%)** | 74 | **failed** (s2, s3; by 1 and 2 rows) |
| R2, tp1 benign blocked | ≤ 3% | 0 | 0 | 0 | 0 | met |
| R3, long11 embedded caught | ≥ 69.0% (174 of 252) | 176 (69.8%) | **171 (67.9%)** | 174 (69.0%) | 171 | **failed** (s2, by 3 documents) |
| R3, long11 benign blocked | ≤ 2 of 49 | 1 | 1 | 0 | 1 | met |
| R4, persona3 EN / VI | ≤ 2% each | 0.5% / 0.9% | 0.8% / 0.9% | 1.0% / 0% | 1.0% / 0.9% | met |
| R4, split2 TPR | ≥ 76.7% | 98.3% | 98.3% | 91.7% | 91.7% | met |
| R4, split2 benign FPR | ≤ 5% | 0% | 3.3% | 0% | 3.3% | met |
| R4, eval/data hold-out TPR at FPR ≤ 1% | ≥ 0.915 | 0.947 | 0.949 | 0.935 | 0.935 | met |

**Verdict: EPL3 is not met.** No seed meets all of R1–R4:
- EPL3-s1 fails R1.
- EPL3-s2 fails R1, R2 and R3.
- EPL3-s3 fails R2.

Under the decision rule, **v8g (EPL2-s3) stays the default** and there is no EPL3 candidate.

## What EPL3 changed

- **Tool poisoning (Pattern A) improved a lot, but not by the pre-registered margin.**
  - tp1 VI: 74–76 of 86 caught, against 59–71 for the v8g band and 59–78 for E. This is +3 to +17 rows over every
    EPL2 seed.
  - tp1 EN: 64 of 64 for every seed, against 42–54 for EPL2.
  - No tp1 benign row was blocked.
  - The R2 bar was the best v8g-band seed + 5 points (76 of 86). Only EPL3-s1 reaches it, and v8e's 78 is still
    above every EPL3 seed.
- **Vietnamese benign blocking got noisier, not lower.**
  - vi1: 5, 10 and 18 of 862, against 4–10 for EPL2 and 7–12 for E.
  - EPL3-s3 is the lowest of nine models, but EPL3-s1 is the highest, driven by 9 of 100 `teencode` template rows
    (EPL2: 1–5).
  - EPL3-s2's blocks are community rows (9 of 562).
  - T+'s teencode and no-diacritics attack forms plausibly pull teencode benign text over the line for some seeds.
    This is not checked at row level, since vi1 is a holdout.
- **Long documents: back inside E's band on average, but one seed is below the bar.**
  - long11 embedded: 171–176, against v8g's 166 and E's 171–179.
  - `split_adjacent` stays the weakest placement for every model (19–21 of 36 for EPL3).
  - Benign blocks are 0–1 of 49, the lowest of any recipe.
- **Retention held.** persona3, split2 and eval/data all pass with room:
  - split2 TPR is 91.7–98.3%, the best of any recipe.
  - persona3 EN is 0.5–1.0%.
  - C2 is 0.935–0.949, inside EPL2's band but under v8g's 0.965.

### Patterns A, B and C on the eval/data dev half (row level; the hold-out half was not read row by row)

| | v8e | E-s2 | E-s3 | EPL2-s1 | EPL2-s2 | v8g | EPL3-s1 | EPL3-s2 | EPL3-s3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A: VI "copy the conversation into a field" attacks caught (13) | 13 | 5 | 9 | 11 | 10 | 6 | **13** | **13** | **13** |
| VI tool_poisoning attacks caught (42) | 42 | 34 | 38 | 40 | 39 | 35 | **42** | **42** | **42** |
| B: `vi-3ae97f4cdc96` / `vi-8205cf9ae1f0` score | 0.97 / 0.97 | 0.99 / 0.02 | 0.03 / 0.01 | 0.04 / 0.07 | 0.05 / 0.03 | 0.03 / 0.10 | 0.09 / 0.55 | 0.88 / 0.02 | 0.04 / 0.07 |
| C: `vi-daf75db21ee6` / `en-78110df48da6` score (benign) | 0.01 / 0.04 | 0.71 / 0.03 | 0.63 / 0.06 | 0.18 / 0.62 | 0.07 / 0.04 | 0.90 / 0.99 | **0.01 / 0.03** | **0.01 / 0.02** | **0.01 / 0.04** |
| VI benign blocked (316) | 2 | 3 | 6 | 3 | 3 | 3 | 4 | 5 | 4 |
| EN benign blocked (178) | 0 | 2 | 1 | 0 | 0 | 1 | 2 | 1 | 3 |
| VI attacks caught (293) | 280 | 274 | 277 | 277 | 266 | 276 | 280 | 285 | 280 |
| EN attacks caught (276) | 250 | 256 | 257 | 257 | 251 | 257 | 253 | 260 | 254 |

- **Pattern A is fixed on dev for every seed:** 13 of 13, and 42 of 42 VI tool_poisoning, against v8g's 6 and 35.
  T+ and O+ closed the thin positive class. On fresh tool poisoning (tp1), 10–12 VI attacks per seed are still
  missed.
- **Pattern B is not fixed.** Only EPL3-s2 catches the `orig` row (0.88), and no seed catches the teencode one. N+
  targeted Pattern C's counterweight, and T+ and O+ did not carry soft overrides ("coi như … không tồn tại"). B is
  the remaining short-path gap against v8e.
- **Pattern C is fixed on dev for every seed.** Both quoted-attack questions score 0.01–0.04, against v8g's 0.90 and
  0.99. N+'s no-diacritics and short-question negatives did what they were built for.
- **New dev false positives:**
  - EPL3-s3 blocks three EN benign rows: a `send_email` tool description, a web-search JSON result and a chat
    message.
  - EPL3-s1 blocks a YAML rule file with `ignore_previous:` and a code comment.
  - These look like T+/O+ field and tool vocabulary leaking into benign tool and config text.
  - The two "Hay tro thanh phien ban tot hon…" rows are still blocked by every model.

## Findings

- **The additions work on their targets but move the seed noise rather than the mean.**
  - A and C are fixed on dev for all three seeds, and fresh tool poisoning rises by 3–17 rows over EPL2.
  - Every seed fails one bar while passing others: s1 on Vietnamese benign, s3 on tool poisoning by two rows, s2 on
    three bars.
  - Across EPL2 and EPL3, the spread between seeds of one recipe is as large as the difference between recipes. This
    is the same reading as R8e's analysis.
- **R1 was the tightest bar and it decided the outcome.**
  - The bar was v8g's own rate (7 of 862), so even an equal-to-v8g seed sits at the bar.
  - Two of three EPL3 seeds exceed it. Under the same bar, v8e (12) and EPL2-s1 (10) would also have failed.
- **R2's margin was close.** Two seeds miss R2 by one and two rows of 86, yet all three beat every EPL2 seed by at
  least three rows.

## What this means

- **v8g stays the default.** No EPL3 seed is a candidate.
- **The next round should keep T+, O+ and N+'s gains and control the Vietnamese benign side.**
  - Pattern B needs its own positives: soft, paraphrased overrides in orig, no-diacritics and teencode forms.
  - Teencode benign rows (and benign tool or config text with field vocabulary) need counterweights.
  - Selection or averaging over seeds (several seeds per run, picked on a dev set) would address the seed variance
    that decides each round. That needs its own pre-registration.
- **vi1, tp1 and long11 are now spent** for EPL3 and the six band models. A new arm needs fresh holdouts, or a
  disclosed re-read.

## Launch erratum

- `colab_job.py` declares `--data` with `nargs="*"` and no append. The pre-registration's block, which repeated
  `--data` per stage directory, would have shipped only the last directory.
- The coordinator launched with one `--data` followed by the seven stage directories, and `--repo . --paths train`,
  from the R8e worktree at `b8435f3`.
- The data, seeds and training command are the pre-registered ones.
- The pre-registration's launch block now reads as run (commit `c5c3701`, marked as an erratum written after the
  launch).

## Limits

- **Small sets.**
  - vi1's templated strata have 100 rows each.
  - tp1 has 86 VI and 64 EN attacks, so R2 turns on one or two rows.
  - long11 has 49 benign documents (English technical text only) and 252 embedded ones from 36 payloads. Its R3
    margin is a few documents.
  - The templated vi1 strata and tp1 were written by the author of T+, O+ and N+, from separate inventories (tools,
    fields, phrasings).
- **The bars are relative to three seeds per band.** As in R8c and R8d, three seeds give the size of the noise, not
  its distribution.
- **Row-level reading is dev only.** The patterns were checked on the eval/data dev half. vi1, tp1 and long11 are
  reported by stratum and placement only.
- **split2 is scored on the conversation window with L2 alone.**
- **Not fresh:**
  - The eval/data hold-out half has been read since R6.
  - persona3 was read in R8c and R8d.
  - split2 was read in R8d.
  - These re-reads are disclosed in the pre-registration.
