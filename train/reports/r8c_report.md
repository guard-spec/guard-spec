# R8c: arm EPL (E + persona hard negatives + long technical windows + payload splitting), three seeds (RF-f9e76bb6)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/r8c_preregistration.md` (commits `606165c` and `69e2664`, the owner's approval).
Training ran on Colab L4 on 2026-11-18/19 (22:36 to 01:11 UTC), one session, three jobs in sequence:

| job | seed | best epoch | training time |
|---|---:|---:|---:|
| EPL-s1 | 20261105 | 5 | 50.4 min |
| EPL-s2 | 20261106 | 4 | 50.5 min |
| EPL-s3 | 20261107 | 5 | 50.5 min |

- **Compute:** about 2.5 h of L4. The account was topped up during the round, so the balance difference does not
  measure the usage.
- **Data:** the staged inputs match the pre-registered SHA-256s (`r8c_L_train`, `r8c_S_train`, `persona_neg_train`,
  `v8e_train`). The data was deleted from the VM before it was stopped.
- **Training set:** each job trained on 72,374 rows (78,165 windows), against 67,005 rows (70,897 windows) for E-s2.
- **Export and calibration:** each model was exported to ONNX INT8 and calibrated with `cmd/calibrate fit` on E's
  12,785 validation rows. E's `long_doc` and `l2_untrusted_max` (0.88) were then added, exactly as in R8b.
  - `model_int8.onnx`: EPL-s1 `38cf4d6e…`, EPL-s2 `f41998e5…`, EPL-s3 `79f26eff…`.
- **Measurement:** `train/measure_r8c.sh` and `train/verdict_r8c.py` (commit `a479d93`). Every holdout was scored
  once per model. Settings: laptop CPU (Apple M3 Max), ONNX Runtime 1.31.1, binaries built at `69e2664` (gateway
  code identical to main `b60056d`).
- **L3:** multilingual-e5-small, `dd476dd0…`. The E band (E = v8e `447c63cd…`, E-s2 `96b074ae…`, E-s3 `3a42317b…`)
  was scored before any EPL model existed.

## Six models

| measure | E | E-s2 | E-s3 | **E band** | EPL-s1 | EPL-s2 | EPL-s3 | **EPL band** |
|---|---:|---:|---:|---|---:|---:|---:|---|
| persona3 EN blocked (396) | 6 (1.5%) | 7 (1.8%) | 9 (2.3%) | 1.5–2.3% | 2 (0.5%) | 3 (0.8%) | 2 (0.5%) | **0.5–0.8%** |
| — enterprise_en (96) | 0 | 0 | 3 | 0–3.1% | 0 | 0 | 0 | 0% |
| — arena_en, community (300) | 6 (2.0%) | 7 (2.3%) | 6 (2.0%) | 2.0–2.3% | 2 (0.7%) | 3 (1.0%) | 2 (0.7%) | **0.7–1.0%** |
| persona3 VI blocked (117) | 2 (1.7%) | 4 (3.4%) | 1 (0.9%) | 0.9–3.4% | 0 | 0 | 1 (0.9%) | **0–0.9%** |
| — enterprise_vi (96) / arena_vi (21) | 2 / 0 | 4 / 0 | 1 / 0 | — | 0 / 0 | 0 / 0 | 1 / 0 | — |
| eval/data hold-out, AUC | 0.989 | 0.987 | 0.988 | 0.987–0.989 | 0.988 | 0.988 | 0.988 | 0.988 |
| eval/data hold-out, TPR at FPR ≤ 1% | 0.960 | 0.915 | 0.925 | 0.915–0.960 | 0.945 | 0.937 | 0.940 | 0.937–0.945 |
| eval/data hold-out, TPR / FPR at 0.85 | 0.937 / 0.0% | 0.932 / 2.0% | 0.952 / 2.0% | — | 0.945 / 1.0% | 0.937 / 1.2% | 0.939 / 1.0% | — |
| long9 benign blocked (49) | 3 | 4 | 5 | 3–5 | 2 | 1 | 0 | **0–2** |
| long9 embedded caught (168) | 148 (88.1%) | 146 (86.9%) | 149 (88.7%) | 86.9–88.7% | 145 (86.3%) | 141 (83.9%) | 145 (86.3%) | 83.9–86.3% |
| long9 payloads alone (24) | 23 | 23 | 23 | — | 23 | 23 | 23 | — |
| split1 TPR, L2 only (60) | 38 (63.3%) | 38 (63.3%) | 43 (71.7%) | 63.3–71.7% | 56 (93.3%) | 54 (90.0%) | 51 (85.0%) | **85.0–93.3%** |
| split1 benign FPR, L2 only (60) | 3 (5.0%) | 4 (6.7%) | 4 (6.7%) | 5.0–6.7% | 4 (6.7%) | 3 (5.0%) | 1 (1.7%) | 1.7–6.7% |

Clopper-Pearson 95% upper bounds, per-stratum counts, and the ids of every blocked benign row and document are in
`train/reports/r8c_holdout.json` and in each model's `summary.json`. On long9, the gateway column (score or
sanitizer anomaly) is equal to the model column for every model; the sanitizer rejected no document.

## Verdict against the pre-registered criteria (each must hold for every EPL seed)

| criterion | bar | EPL-s1 | EPL-s2 | EPL-s3 | worst seed | result |
|---|---|---|---|---|---|---|
| C1, persona3 EN blocked | ≤ 5% | 0.5% (CP95 1.8%) | 0.8% (2.2%) | 0.5% (1.8%) | 0.8% | **met** |
| C1, persona3 VI blocked | ≤ 5% | 0% (CP95 3.1%) | 0% (3.1%) | 0.9% (4.7%) | 0.9% | **met** |
| C1, arena_en (reported; aim: below E's band, 2.0–2.3%) | — | 0.7% | 1.0% | 0.7% | 1.0% | below the band |
| C2, eval/data hold-out TPR at FPR ≤ 1% | ≥ 0.915 | 0.945 | 0.937 | 0.940 | 0.937 | **met** |
| C3, long9 benign blocked | ≤ 5 (E's worst seed) | 2 | 1 | 0 | 2 | **met** |
| C3, long9 embedded caught | ≥ 86.9% − 2 points = 84.9% | 86.3% | **83.9%** (141/168) | 86.3% | 83.9% | **not met** (EPL-s2) |
| C4, split1 TPR | > 71.7% (E's best seed) | 93.3% | 90.0% | 85.0% | 85.0% | met |
| C4, split1 benign FPR | ≤ 5% | **6.7%** (4/60) | 5.0% | 1.7% | 6.7% | **not met** (EPL-s1) |

**Verdict: EPL is not met.**
- EPL-s1 fails C4: its split1 benign FPR is 6.7% against a bar of 5%.
- EPL-s2 fails C3: it catches 83.9% of long9's embedded attacks against a bar of 84.9%.
- EPL-s3 meets every criterion.

Under the pre-registered decision rule, every seed must pass, so **E (v8e) stays the candidate**.

## What EPL blocks

- **persona3.** The EPL seeds block 2–3 English rows and at most one Vietnamese row:
  - two or three community prompts (`arena_en`); one of them is blocked by all three seeds;
  - for EPL-s3, one Vietnamese enterprise prompt.

  E blocks 6–9 English rows and 1–4 Vietnamese ones; EPL-s1 and EPL-s2 block no Vietnamese row.
- **long9 benign.** EPL-s1 blocks 2 `docs` documents, EPL-s2 one and EPL-s3 none. All E seeds block
  `long9-docs-en-100000-2`, and EPL-s1 and EPL-s2 still block it; EPL-s3 does not. E's other blocks are also
  docs documents (the VS Code and OpenTelemetry documentation, mixed), plus one man-pages document for E-s3.
- **long9 embedded.** The EPL seeds lose 1–7 embedded documents against E's seeds, spread over the placements.
  EPL-s2 loses most at `pos_start`, `pos_random` and `straddle_window` (20 of 24 each, against 21–24 for E).
  `split_adjacent` stays at 17–18 of 24 for every model.
- **split1 benign.** The blocked conversations are the "don't ignore the previous instructions" hard negatives in
  both languages, plus one Vietnamese word game (EPL-s1). Three of EPL-s1's four blocks are `dont_ignore`. All
  three EPL seeds block `split1-ben-en-07`.

## Findings

- **The persona fix holds and the long-document cost of R8b's E+P is gone.** Every EPL seed blocks fewer benign
  persona rows than every E seed, in both languages and on the community stratum (0.7–1.0% against 2.0–2.3%). Every
  EPL seed blocks fewer benign long9 documents than every E seed (0–2 against 3–5). The L windows did what R8b's
  report proposed.
- **E itself blocks 3–5 of 49 benign long9 documents.** These are long technical documentation (VS Code,
  OpenTelemetry), a genre long5 had little of. The shipped v8e has a long-document false-positive rate on this
  genre that long5 did not show (6–10% of documents, CP95 upper 17–22%). C3's bar is relative to that band, so
  "met" there means "no worse than E", not "good".
- **Payload splitting.** S lifts L2's split1 detection from 63–72% to 85–93% for every seed. E's band leaves room
  for this: on the window alone, E misses about a third of the split attacks.
- **C4's FPR bar is tight against E.** E's own seeds sit at 5.0–6.7% on split1's benign conversations, so the
  ≤ 5% bar fails two of E's three seeds. EPL-s1 fails it by one conversation (4 of 60 against 3). With 60
  conversations, one conversation is 1.7 points. Counting a block on the window or any single turn (supplementary,
  not a criterion), E's FPR is 10–13% and EPL's 5–10%.
- **Detection of embedded attacks moved down a little.** The EPL seeds catch 83.9–86.3% on long9 against E's
  86.9–88.7%. The two bands overlap at their edges only. EPL-s2's miss of the bar is 2 documents of 168 (141
  against 143 needed). The L attack windows did not keep detection fully level; the benign L windows may have
  pulled long documentation scores down slightly overall.
- **eval/data stays inside E's band** (0.937–0.945, AUC 0.988), so the additions cost nothing on the short path.
- **Seed noise is again as large as the criteria's margins.** Two of the three EPL seeds fail by one or two
  documents or conversations, and one passes everything. As in R8b, the decision is sensitive to the seed.

## What this means

- **v8e stays the candidate**, as pre-registered. EPL-s3 alone meets every criterion; under the rule it is not
  the candidate, and choosing it now, after seeing all three, would be choosing on the holdout.
- **A next round could keep L, S and the persona rows,** and address the two failing measures:
  - the "don't ignore the previous instructions" hard negatives of payload splitting (more and more varied
    benign rows of that shape in S);
  - embedded detection in long documentation (more attack windows than benign ones in L, or harder placements
    such as `split_adjacent`).

  persona3, long9 and split1 are now spent; such a round needs fresh holdouts.
- **Long technical documentation is a weak spot of v8e itself** (3–5 of 49 on long9), independent of R8c's
  verdict. Whether to act on it before a new model is the owner's decision.

## Limits

- **Small samples, wide bounds.**
  - long9 has 49 benign documents (English technical text only) and 168 embedded ones (24 payloads).
  - split1 has 60 + 60 conversations from templates written by the author of S, in separate phrasings.
  - persona3's enterprise prompts are template-generated, and its Vietnamese community stratum is 21 rows.
- **Three seeds per arm** give the size of the noise, not its distribution.
- **split1 is scored on the conversation window with L2 alone.** In the gateway, the L1 rules (the payload_split
  rule of RF-53b1d175 among them) and the per-turn scores also decide.
- **Not fresh:** the eval/data hold-out half has been read since R6. The E band was scored on long9 before the
  EPL models existed; both are R8c's first and only reads of these holdouts.
