# R8d pre-registration: arm EPL2 (EPL + L+ attack windows + N negated-override negatives), three seeds (RF-e82b0347)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-19, before any R8d training job. `long10` and `split2` have been scored by no model except arm E's
three seeds, which the pre-registration allows (the E band, below). The data was built on the laptop only
(`train/data/build_r8d_holdouts.py`, `train/data/build_r8d.py`).

**Owner approval:** on 2026-11-19, in chat, the owner approved sending the R8d training data to Colab for the
three R8d jobs only ("Đồng ý đưa data lên colab"). The data is E's data (owner rows included),
`persona_neg_train.jsonl`, R8c's `r8c_L_train.jsonl` and `r8c_S_train.jsonl`, and R8d's `r8d_Lplus_train.jsonl` and
`r8d_N_train.jsonl`.

## Problem and hypothesis

R8c (`r8c_report.md`): arm EPL was not met, and v8e stayed.

- EPL-s2 caught 83.9% of long9's embedded attacks against a bar of 84.9%.
- EPL-s1 blocked 4 of 60 benign split1 conversations against a bar of 3; three of the four were "don't ignore the
  previous instructions" conversations.
- EPL-s3 met every criterion.
- EPL fixed the persona and long-document false positives of R8b's E+P, and lifted L2's detection of split payloads
  from 63–72% to 85–93%.

**Hypothesis.** EPL2 adds the following to EPL's data:
- more payload-carrying windows of long technical documentation (`L+`, about 1 : 1.7 benign : attack for the long
  technical windows instead of 1 : 1);
- hard negatives of negated and quoted overrides (`N`).

With these, every seed keeps EPL's gains and meets the two bars two of EPL's seeds missed.

## Jobs (Colab L4, sequential)

| job | data | seed |
|---|---|---:|
| `EPL2-s1` | E's data (`data-v4A`, `out-full`, `v8e_train.jsonl`) + `persona_neg_train.jsonl` + `r8c_L_train.jsonl` + `r8c_S_train.jsonl` + `r8d_Lplus_train.jsonl` + `r8d_N_train.jsonl` | 20261105 |
| `EPL2-s2` | same | 20261106 |
| `EPL2-s3` | same | 20261107 |

```
cd train && python3 train.py --data-dir "$DATA_DIR/data-v4A" --v6-dir "$DATA_DIR/out-full" --v8-dir "$DATA_DIR/v8" \
    --v8-file v8e_train.jsonl --extra-train "$DATA_DIR/r8b/persona_neg_train.jsonl" \
    --extra-train "$DATA_DIR/r8c/r8c_L_train.jsonl" --extra-train "$DATA_DIR/r8c/r8c_S_train.jsonl" \
    --extra-train "$DATA_DIR/r8d/r8d_Lplus_train.jsonl" --extra-train "$DATA_DIR/r8d/r8d_N_train.jsonl" \
    --seed <seed> --run-dir "$OUT_DIR/EPL2-s<k>"
```

Every model is exported to ONNX INT8 and calibrated with `cmd/calibrate fit` on E's 12,785 validation rows, then
given E's `long_doc` and `l2_untrusted_max` (0.88), exactly as in R8b and R8c. The comparator is arm E's seed band:
E (v8e, 20261105), E-s2 (20261106), E-s3 (20261107), not retrained. EPL's three seeds (R8c) are context only.

## Data

### Training additions (`build_r8d.py`, seed 20261120)

| file | rows | SHA-256 |
|---|---|---|
| `r8d_Lplus_train.jsonl` (L+) | 1,000 embedded-attack windows (docs 450, rfc 300, readme 250), no benign row | `dae8aba367cc59c15bdb53b7d01310c684b5e77bb4d1fb2038e2968d43d77a79` |
| `r8d_N_train.jsonl` (N) | 400 benign: EN 200, VI 200; negated 134, quoted 134, split over turns 132 | `e6b9b47e119740fcd47e5e1b27f9b0acaa09c8ed9b0b00d56f45259fb22c6cab` |
| `r8c_L_train.jsonl` (R8c, unchanged) | 2,996 | `7bd8a1c0b7a602ab0cf5819240374b45e2e46a8d58d6d3c5953cc98b3d38530b` |
| `r8c_S_train.jsonl` (R8c, unchanged) | 800 | `19a9087fa71365ed1bb9a5db58dcdd34c09a998770dd6843da30fe9a9372bff1` |
| `persona_neg_train.jsonl` (R8b, unchanged) | 1,573 | `74aecfc6165e9ca348fd47ca78e0f3aa4adc0ba449db73383bad43ffe021ca20` |
| `v8e_train.jsonl` (E, unchanged) | 16,906 | `7f51cdb409fa4af9121b30ddc8708e7aa1cac186d33f668fa7a614b433195550` |

- **L+ sources** (`train/data/sources_r8d.yaml`, each pinned by commit, tree SHA and extracted-text SHA-256):
  - docs: the Apache Airflow documentation (3.4.0, Apache-2.0), the Open Policy Agent documentation (v1.22.4,
    Apache-2.0) and the cert-manager documentation (Apache-2.0);
  - rfc: 41 RFCs, every twentieth from the eighth of R8c's 815 candidates;
  - readme: the Datadog integration READMEs (BSD-3-Clause).

  None of these is used by a bench/long profile (long9 and long10 included), by an earlier training source or by
  R8c's L.
- **Pool:** 95 documents, 3.21M tokens, SHA-256 `840eed75…a8c43`; sanitized by the gateway's sanitizer,
  SHA-256 `1e9439ca…fa03`.
- **L+ attack windows:**
  - Placements are build_v8's: mid 304, split_within 168, straddle_window 147, split_adjacent 142, start 120, end 119.
  - Payloads: 1,000 distinct training payloads of set A, English. They are drawn from the same usable pool as R8c's
    L, with this round's seed, so a payload can appear in both in different hosts.
  - Gateway windows: 1,047 attack, 77 benign, 96 dropped by the labelling shares.
  - With L's 1,500 benign and 1,496 attack rows, the long technical windows go from 1 : 1 to 1,500 : 2,496 (1 : 1.66).
- **N:** `data/r8d_templates.py` `n_rows`. Its frames are not split1's, split2's, S's, multiturn.json's or the
  payload_split dev set's. R8c's split1 false positives were read for the kind of failure only.
- Built twice, byte-identical. Counts are in `stats_r8d.json` (SHA-256 `dc627cd0…44c8`), summarised in
  `train/reports/r8d_build_report.json`.

### Holdouts

| holdout | contents | SHA-256 |
|---|---|---|
| `long10` benign (`outputs.long10`) | 52 English documents, 7.80M tokens: docs 8 + 8, rfc 7 + 7, readme 7 + 7, man 4 + 4 at 100k + 200k | `85f568096c2b3fd1bcc6407656760d117397491f2520897803bcff30c7fd1174` |
| `long10` attack | 168 embedded-attack documents and 24 payloads alone (`embed_long.py --eval-payloads 24 --eval-skip 168 --langs en`; eval/ dev-half English rows 168 to 191) | `77408aeb9351238d63219e1cf178075383b6cc4c75241a99702e623391c34c2d` |
| `split2/split2.json` | 120 conversations: attack EN 30, VI 30; benign EN 30, VI 30 (negated overrides 13, quoted 7, joins and sums 10 per language); 2 to 3 user turns | `15b6518435ed775594386d5b9bd222ae9d5a11ed914e2ab93cc006ed3cd13146` |
| `persona3` (R8c, reused) | EN 396, VI 117 | `07daf55d…dfeadf`, `7dc19996…7d65dc` |

- **long10 sources:**
  - docs: scikit-learn 1.9.1, NumPy, the Rust reference and the rustc dev guide (all BSD or MIT/Apache), Knative
    (Apache-2.0) and gRPC (CC-BY-4.0);
  - rfc: 82 RFCs, every tenth from the third of the 815 candidates;
  - readme: Bitnami charts (Apache-2.0) and AWS Serverless Patterns (MIT-0);
  - man: FreeBSD manual pages, sections 4, 5, 7 and 9 (BSD).
- **long10 exclusions:** `exclude.json` drops 173 units:
  - 163 share a 50-token run with E's data, persona_neg_train, the v7 pool or R8c's L and S. 114 of these are Bitnami
    READMEs, which earlier training text overlaps.
  - 10 are 20% near-duplicates of another profile's document.

  Built twice, same SHA-256.
- **persona3** was built for R8c and R8d was not designed on it. E's three seeds and EPL's three seeds have read it
  once each; EPL2 reads it once. It stays the C1 set.

### Overlap and guard checks

- Holdouts against every guarded text (`build_r8d_holdouts.py check`, `holdout_check.json`): **clean**.
  - Checked: split2 (438 turns and joined conversations) and long10 (244 documents).
  - Guarded texts: E's data, persona_neg_train, R8c's L and S, R8d's L+ and N, eval/, persona1, persona2, persona3,
    split1, the exemplars, multiturn.json, the payload_split dev set and the repository's train/data rows.
  - Rule for split2: exact, or half of the row's 8-word shingles. Rule for long10: 50-token runs against the training
    rows.
- L+ and N against bench/long and the hold-outs (`build_r8d.py check`, `guard_r8d.json`): **clean**.
  - 1,000 of 1,000 and 400 of 400 rows are clean of 50-token runs, with 0 12-token runs of short hold-out rows and 0
    overlaps by the 8-word rule in either direction.
  - Index: bench/long quick to long10, the embedded-attack documents of R5 and long6 to long10, and every hold-out
    row (split2 included).
- The owner hold-outs are never read; E's files are read only for comparison.

## Measures (ONNX INT8, laptop CPU, gateway path; `train/measure_r8c.sh` and `train/verdict_r8c.py`)

- **E band (E, E-s2, E-s3):**
  - `long10` and `split2`: scored once in R8d, before any EPL2 job.
  - `persona3` and `eval/data`: their R8c runs.
- **EPL2-s1..s3:** every measure, once.
- **EPL (R8c):** reported for context, no role in the criteria.

1. `persona3` (`cmd/eval -path direct`): benign blocked per language and per stratum, with the CP95 upper bound.
2. `eval/data` hold-out half: TPR at FPR ≤ 1%; TPR/FPR at 0.85.
3. `long10` (`cmd/benchlong -long on`, shipped `long_doc`, each model's own calibration): benign documents blocked
   (doc_score ≥ 0.85), embedded attacks caught, payloads alone caught.
4. `split2`: L2 alone on the conversation window (the user turns joined with a space): TPR of the 60 attack
   conversations and FPR of the 60 benign ones at the gateway decision; per-turn maxima are supplementary.

## Criteria (identical to R8c, with long10 and split2; each must hold for every EPL2 seed)

| | criterion | bar |
|---|---|---|
| **C1** | `persona3` benign blocked, per language | ≤ 5%, with the CP95 upper bound reported; the community EN stratum is reported separately and should sit below E's band (aim, not a pass/fail bar) |
| **C2** | `eval/data` hold-out half, TPR at FPR ≤ 1% | ≥ 0.915 (E's lowest seed, R8b) |
| **C3** | `long10` benign documents blocked | ≤ the worst of E's three seeds on `long10` |
| **C3** | `long10` embedded attacks caught | ≥ E's lowest seed on `long10` − 2 points |
| **C4** | `split2`, L2 only | TPR above E's band (higher than E's best seed) and benign FPR ≤ 5% |

`python3 train/verdict_r8c.py verdict --arm EPL2 --long long10 --split split2 --measure <R8c measure dir>
--measure <R8d measure dir> --out train/reports/r8d_holdout.json` applies them.

### The E band on long10 and split2 (scored on 2026-11-19, before any EPL2 job; binaries at `60e375d`)

| measure | E (v8e) | E-s2 | E-s3 | band | bar for every EPL2 seed |
|---|---:|---:|---:|---|---|
| long10 benign blocked (52) | 4 | 2 | 6 | 2–6 | C3: ≤ 6 |
| long10 embedded caught (168) | 134 (79.8%) | 127 (75.6%) | 139 (82.7%) | 75.6–82.7% | C3: ≥ 73.6% (124 of 168) |
| long10 payloads alone (24) | 21 | 21 | 21 | — | — |
| split2 TPR, L2 only (60) | 42 (70.0%) | 40 (66.7%) | 43 (71.7%) | 66.7–71.7% | C4: > 71.7% (44 of 60 or more) |
| split2 benign FPR, L2 only (60) | 1 (1.7%) | 5 (8.3%) | 0 | 0–8.3% | C4: ≤ 5% (3 of 60 at most) |

From R8c, unchanged:
- persona3 community EN (`arena_en`): 2.0–2.3% blocked; C1 aims below this.
- eval/data hold-out TPR at FPR ≤ 1%: 0.915–0.960.

What the E band shows:
- On long10, E's benign blocks are docs, man, rfc and readme documents. E-s2's split2 false positives are all
  negated-override conversations (5 of 5), which is the failure N targets.
- The per-turn maximum (supplementary) gives E an FPR of 16.7–20.0% on split2.


## Decision

- If every EPL2 seed meets C1–C4, EPL2 becomes the candidate for the next model package, in shadow mode first. The
  seed to package is the one with the highest C2 among them. Making it the default stays the owner's decision.
- If any EPL2 seed fails a criterion, the report names the seed and the criterion, and E (v8e) stays the candidate.
- No threshold, rule or calibration is tuned on `persona3`, `long10` or `split2`. Each is scored once per model.

## Limits

- **Small sets.**
  - long10 has 52 benign documents of English technical text only.
  - split2 has 60 + 60 conversations from templates by the author of S and N, in separate phrasings.
  - persona3's enterprise prompts are template-generated, and its Vietnamese community stratum has 21 rows.
- **Bars sensitive to one item.** On split2, one benign conversation is 1.7 points of FPR, and E's band on split1 was
  already at the 5% bar.
- **Three seeds** give the size of the noise, not its distribution.
