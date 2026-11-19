# R8d: arm EPL2 (EPL + L+ attack windows + N negated-override negatives), three seeds (RF-e82b0347)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/r8d_preregistration.md` (commit `ad1c6ad`, with the owner's approval of 2026-11-19 to
send the data). Training ran on Colab L4 on 2026-11-19 (11:15 to 13:48 UTC), one session, three jobs in sequence:

| job | seed | best epoch | training time |
|---|---:|---:|---:|
| EPL2-s1 | 20261105 | 5 | 49.8 min |
| EPL2-s2 | 20261106 | 4 | 49.8 min |
| EPL2-s3 | 20261107 | 4 | 49.8 min |

- **Compute:** 572.26 → 567.11 units (5.15).
- **Data:** the staged inputs match the pre-registered SHA-256s (`r8d_Lplus_train`, `r8d_N_train` and EPL's files).
  The data was deleted from the VM before it was stopped.
- **Training set:** each job trained on 73,774 rows (79,689 windows), against 72,374 for EPL.
- **Export and calibration:** each model was exported to ONNX INT8 and calibrated with `cmd/calibrate fit` on E's
  12,785 validation rows. E's `long_doc` and `l2_untrusted_max` (0.88) were then added, as in R8b and R8c.
  - `model_int8.onnx`: EPL2-s1 `de71a893…`, EPL2-s2 `4687e25a…`, EPL2-s3 `b68cfbe8…`.
- **Measurement:** `train/measure_r8c.sh` and `train/verdict_r8c.py`. Every holdout was scored once per model.
  Settings: laptop CPU (Apple M3 Max), binaries built at `60e375d` (gateway code identical to main), L3
  multilingual-e5-small `dd476dd0…`.
- **E band sources:** long10 and split2 were scored in R8d before any EPL2 job; persona3 and eval/data are E's R8c
  runs.

## Nine models

EPL (R8c) is context only: it was scored on persona3 and eval/data, not on long10 or split2.

| measure | E | E-s2 | E-s3 | **E band** | EPL2-s1 | EPL2-s2 | EPL2-s3 | **EPL2 band** | EPL band (R8c) |
|---|---:|---:|---:|---|---:|---:|---:|---|---|
| persona3 EN blocked (396) | 6 (1.5%) | 7 (1.8%) | 9 (2.3%) | 1.5–2.3% | 2 (0.5%) | 5 (1.3%) | 1 (0.3%) | **0.3–1.3%** | 0.5–0.8% |
| — arena_en, community (300) | 6 (2.0%) | 7 (2.3%) | 6 (2.0%) | 2.0–2.3% | 2 (0.7%) | 5 (1.7%) | 1 (0.3%) | **0.3–1.7%** | 0.7–1.0% |
| — enterprise_en (96) | 0 | 0 | 3 | 0–3.1% | 0 | 0 | 0 | 0% | 0% |
| persona3 VI blocked (117) | 2 (1.7%) | 4 (3.4%) | 1 (0.9%) | 0.9–3.4% | 3 (2.6%) | 0 | 1 (0.9%) | 0–2.6% | 0–0.9% |
| — enterprise_vi (96) / arena_vi (21) | 2 / 0 | 4 / 0 | 1 / 0 | — | 3 / 0 | 0 / 0 | 1 / 0 | — | — |
| eval/data hold-out, AUC | 0.989 | 0.987 | 0.988 | 0.987–0.989 | 0.989 | 0.988 | 0.991 | 0.988–0.991 | 0.988 |
| eval/data hold-out, TPR at FPR ≤ 1% | 0.960 | 0.915 | 0.925 | 0.915–0.960 | 0.952 | 0.942 | **0.965** | 0.942–0.965 | 0.937–0.945 |
| eval/data hold-out, TPR / FPR at 0.85 | 0.937 / 0.0% | 0.932 / 2.0% | 0.952 / 2.0% | — | 0.945 / 0.6% | 0.904 / 0.0% | 0.959 / 1.0% | — | — |
| long10 benign blocked (52) | 4 | 2 | 6 | 2–6 | 3 | 3 | 1 | 1–3 | — |
| long10 embedded caught (168) | 134 (79.8%) | 127 (75.6%) | 139 (82.7%) | 75.6–82.7% | 132 (78.6%) | 134 (79.8%) | 124 (73.8%) | 73.8–79.8% | — |
| long10 payloads alone (24) | 21 | 21 | 21 | — | 21 | 21 | 21 | — | — |
| split2 TPR, L2 only (60) | 42 (70.0%) | 40 (66.7%) | 43 (71.7%) | 66.7–71.7% | 56 (93.3%) | 49 (81.7%) | 56 (93.3%) | **81.7–93.3%** | — |
| split2 benign FPR, L2 only (60) | 1 (1.7%) | 5 (8.3%) | 0 | 0–8.3% | 0 | 0 | 2 (3.3%) | **0–3.3%** | — |

The CP95 upper bounds, the ids of every blocked benign row and document, and the missed split2 attacks are in
`train/reports/r8d_holdout.json` and in each model's `summary.json`. The sanitizer rejected no long10 document.

## Verdict against the pre-registered criteria (each must hold for every EPL2 seed)

| criterion | bar | EPL2-s1 | EPL2-s2 | EPL2-s3 | worst seed | result |
|---|---|---|---|---|---|---|
| C1, persona3 EN blocked | ≤ 5% | 0.5% (CP95 1.8%) | 1.3% (2.9%) | 0.3% (1.4%) | 1.3% | **met** |
| C1, persona3 VI blocked | ≤ 5% | 2.6% (CP95 7.3%) | 0% (3.1%) | 0.9% (4.7%) | 2.6% | **met** |
| C1, arena_en (reported; aim: below E's 2.0–2.3%) | — | 0.7% | 1.7% | 0.3% | 1.7% | below the band |
| C2, eval/data hold-out TPR at FPR ≤ 1% | ≥ 0.915 | 0.952 | 0.942 | 0.965 | 0.942 | **met** |
| C3, long10 benign blocked | ≤ 6 (E's worst seed) | 3 | 3 | 1 | 3 | **met** |
| C3, long10 embedded caught | ≥ 75.6% − 2 points = 73.6% | 78.6% | 79.8% | 73.8% (124/168) | 73.8% | **met** (EPL2-s3 at the bar: 124 needed) |
| C4, split2 TPR | > 71.7% (E's best seed) | 93.3% | 81.7% | 93.3% | 81.7% | **met** |
| C4, split2 benign FPR | ≤ 5% | 0% | 0% | 3.3% (2/60) | 3.3% | **met** |

**Verdict: EPL2 is met.** Every seed meets C1–C4. Under the decision rule:
- **EPL2-s3**, the seed with the highest C2 (0.965), becomes the candidate for the next model package, in shadow
  mode first.
- Making it the default stays the owner's decision.

## What EPL2 blocks and misses

- **persona3.**
  - EPL2-s1 blocks 2 community EN rows and 3 Vietnamese enterprise prompts.
  - EPL2-s2 blocks 5 community EN rows and no Vietnamese row.
  - EPL2-s3 blocks 1 community EN row and 1 Vietnamese enterprise prompt.
  - One community EN row is blocked by EPL2-s1, EPL2-s2 and all three EPL seeds.
- **long10 benign.**
  - EPL2's blocks are man and readme documents, plus one docs document for EPL2-s2.
  - `long10-man-en-200000-0` is blocked by every EPL2 seed and by E and E-s3.
  - E's three seeds all block `long10-docs-en-100000-2`. EPL2-s1 and EPL2-s3 do not; EPL2-s2 still does.
- **long10 embedded.** EPL2-s3 catches 124 of 168, the lowest of the six models and exactly at the bar. Its losses
  against E's seeds are spread over the placements, `split_adjacent` (14 of 24) and `straddle_chunk` (19 of 24) most.
- **split2.**
  - Benign: EPL2-s3's two blocks are negated-override conversations (one EN, one VI); EPL2-s1 and EPL2-s2 block none.
    E-s2 had blocked five of this kind.
  - Missed attacks: mostly the `cipher` and `list` frames (clues to assemble, `item_a + item_b`). EPL2-s2 misses 11,
    including `halves` and `swap` ones.

## Findings

- **N fixed the negated-override false positives on fresh conversations.** split2's benign FPR is 0–3.3% for EPL2
  against 0–8.3% for E. EPL's failure in R8c (4 of 60 on split1) does not recur on split2's new phrasings. With
  per-turn maxima counted as well (supplementary), EPL2 sits at 3.3–11.7% against E's 16.7–20%.
- **Payload splitting stays caught.** L2's split2 TPR is 81.7–93.3% against E's 66.7–71.7%.
- **The persona fix holds.** persona3 EN is 0.3–1.3% against E's 1.5–2.3%. The community stratum is below E's band
  for every seed (0.3–1.7% against 2.0–2.3%).
- **Long documents: fewer benign blocks, embedded detection inside E's band but at its bottom edge.** long10 benign
  blocks are 1–3 against E's 2–6. Embedded detection is 73.8–79.8% against E's 75.6–82.7%, with EPL2-s3 exactly at
  the bar. L+ did not lift embedded detection above E; it kept it from falling the way EPL-s2's did on long9.
- **The candidate seed is the weakest on embedded detection.** EPL2-s3 is the strongest on eval/data (0.965, above
  E's 0.960), persona3 (0.3% EN) and long10 benign (1 of 52), and the weakest on long10 embedded (73.8%). The
  pre-registered rule picks it on C2.
- **EPL2-s2's calibration is unusual.** Its Platt intercept is +0.83, against −0.19 and −0.66 for the other two seeds
  and −0.07 to −0.22 for EPL. Its TPR at 0.85 on eval/data is 0.904, the lowest of the nine models, though its TPR at
  FPR ≤ 1% is 0.942. This does not affect the verdict, since EPL2-s3 is the candidate, but the export should be
  re-checked before EPL2-s2 is used for anything.
- **long10 is harder than long9 for every model** (E catches 75.6–82.7% against 86.9–88.7% on long9). C3 is relative
  to E's band, so it adjusts; an absolute bar would have been met by no model.

## What this means

- **EPL2-s3 is the candidate for the next model package** (v8f), in shadow mode first, as pre-registered. Making it
  the default stays the owner's decision.
- **Before release**, the package checks (fp16 export and agreement, parity, the gateway eval) apply as for v8e.
  EPL2-s3's long10 embedded margin is zero documents, so embedded detection in long documentation should be watched
  in shadow mode.
- **persona3, long10 and split2 are now spent.**

## Limits

- **Small sets.**
  - long10 has 52 benign documents (English technical text only) and 168 embedded ones (24 payloads).
  - split2 has 60 + 60 template conversations by the author of S and N, in separate phrasings.
  - persona3's enterprise prompts are templates, and its Vietnamese community stratum has 21 rows.
- **The bars are relative to E's three seeds.** Three seeds give the size of the noise, not its distribution, and
  EPL2-s3 passes C3 by zero documents.
- **split2 is scored on the conversation window with L2 alone.** In the gateway, the L1 rules (payload_split among
  them) and the per-turn scores also decide.
- **Not fresh:** the eval/data hold-out half has been read since R6, and persona3 was read in R8c by E and EPL.
