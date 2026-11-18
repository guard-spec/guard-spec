# R8c pre-registration: arm EPL (E + persona hard negatives + long technical windows + payload splitting), three seeds (RF-f9e76bb6)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-19, before any R8c training job, and before `persona3`, `long9` or `split1` was scored by any
model or rule layer. The data was built on the laptop only (`train/data/build_r8c_holdouts.py`,
`train/data/build_r8c.py`); nothing has left it.

> **TODO (lead):** the owner approved sending the EPL training data (E's data, owner rows included,
> `persona_neg_train.jsonl` and the R8c files below) to Colab for these jobs: _date, link to the approval_.

## Problem and hypothesis

R8b (`r8b_report.md`): arm E+P (E's data plus 1,573 benign persona rows) cut English persona false positives on
`persona2` from 3.3% to 0.5%, but blocked 4 of 150 benign long English technical documents of `long5` (three
`docs`, one `rfc`) against a bar of 1. A plausible reading: long instruction-shaped prompts sent as benign moved the
model's view of imperative technical prose.

**Hypothesis.** Adding benign windows of long technical documentation, each paired with a window of the same host
carrying a training payload (the build_v8 scheme, `L`), keeps E+P's persona gain without the long-document cost.
Adding payload-splitting attacks and hard negatives (`S`) lets L2 see a split instruction joined by the
conversation window.

## Jobs (Colab L4, sequential)

| job | data | seed |
|---|---|---:|
| `EPL-s1` | E's data (`data-v4A`, `out-full`, `v8e_train.jsonl`, unchanged) + `persona_neg_train.jsonl` + `r8c_L_train.jsonl` + `r8c_S_train.jsonl` | 20261105 |
| `EPL-s2` | same | 20261106 |
| `EPL-s3` | same | 20261107 |

```
cd train && python3 train.py --data-dir "$DATA_DIR/data-v4A" --v6-dir "$DATA_DIR/out-full" --v8-dir "$DATA_DIR/v8" \
    --v8-file v8e_train.jsonl --extra-train "$DATA_DIR/r8b/persona_neg_train.jsonl" \
    --extra-train "$DATA_DIR/r8c/r8c_L_train.jsonl" --extra-train "$DATA_DIR/r8c/r8c_S_train.jsonl" \
    --seed <seed> --run-dir "$OUT_DIR/EPL-s<k>"
```

Every model is exported to ONNX INT8 and calibrated with `cmd/calibrate fit` on E's validation rows (12,785), then
given E's `long_doc` and `l2_untrusted_max` (0.88) blocks, as in R8b. The comparator is arm E's seed band of R8b:
E (v8e, 20261105), E-s2 (20261106), E-s3 (20261107), not retrained.

## Data

### Training additions (`build_r8c.py`, seed 20261119)

| file | rows | SHA-256 |
|---|---|---|
| `r8c_L_train.jsonl` (L) | 2,996: 1,500 benign windows (docs 550, rfc 350, readme 300, man 300) + 1,496 embedded-attack windows | `7bd8a1c0b7a602ab0cf5819240374b45e2e46a8d58d6d3c5953cc98b3d38530b` |
| `r8c_S_train.jsonl` (S) | 800: 400 payload-splitting attacks (EN 200, VI 200) + 400 hard negatives (EN 200, VI 200) | `19a9087fa71365ed1bb9a5db58dcdd34c09a998770dd6843da30fe9a9372bff1` |
| `persona_neg_train.jsonl` (R8b, unchanged) | 1,573 | `74aecfc6165e9ca348fd47ca78e0f3aa4adc0ba449db73383bad43ffe021ca20` |
| `v8e_train.jsonl` (E, unchanged) | 16,906 | `7f51cdb409fa4af9121b30ddc8708e7aa1cac186d33f668fa7a614b433195550` |

- **L sources** (`train/data/sources_r8c.yaml`, every one pinned by commit, tree SHA and extracted-text SHA-256):
  - docs: the Envoy documentation (envoyproxy/envoy v1.40.2, Apache-2.0) and the Cilium documentation
    (cilium/cilium v1.20.5, Apache-2.0);
  - rfc: 41 RFCs (IETF Trust, BCP 78);
  - readme: the Telegraf plugin READMEs (influxdata/telegraf v1.40.3, MIT);
  - man: the OpenBSD manual pages of share/man and usr.bin (openbsd/src mirror, ISC/BSD), roff turned into text.

  The RFCs are every twentieth, from the sixth, of 815 candidates. The candidates are RFCs from 2000 on of 40 to
  200 pages, with a text file, not obsoleted, standards track, BCP or informational, and named nowhere in bench/,
  train/ or eval/ (`rfc-index.xml` of 2026-11-19, SHA-256 `12be47b6…ce9c7`). long9 takes every tenth from the
  first, so the two lists are disjoint.
- **The pool.** Every unit that shares a run of 50 classifier tokens with any of the following is dropped or
  trimmed to its clean paragraphs (`pool_report.json`): a bench/long document (quick, full, long, long5 to
  long9), an embedded-attack document (R5, long6, long7, long8, long9) or a hold-out row. 127 documents, 4.18M
  tokens, SHA-256 `032ad96b…88777c`. The pool is sanitized by the gateway's sanitizer, SHA-256
  `11eef3a8…203781f`.
- **L windows.** Benign windows are a seeded sample of the gateway windows (254 content tokens, step 190). Each
  host gets one window of the same host with a payload, through build_v8's own functions and placements: mid 462,
  split_adjacent 201, split_within 220, straddle_window 241, start 199, end 173. Four readme hosts got no attack
  (split_within did not fit).
- **L payloads.** Attack rows of `data/train.jsonl` (SHA-256 `4886a86d…199c16`), payload set A, English. A payload
  is skipped when any of the following holds:
  - it is a validation, hold-out or probe row, or an eval/ fingerprint;
  - it shares a guard run with the hold-outs;
  - its 8-word shingles overlap a hold-out row or an L3 exemplar in either direction (101 skipped: the exemplars
    are copies of `train.jsonl` rows).

  1,496 distinct payloads, each used once. Gateway windows: 1,701 benign and 1,570 attack, plus 108 benign windows
  of attack rows (160 dropped by the labelling shares).
- **S.** `data/r8c_templates.py` `s_rows`, labels `obfuscation` plus the intent: `direct_injection` 108,
  `prompt_extraction` 100, `jailbreak` 100, `data_exfiltration` 92. Its frames and fragments are not split1's,
  multiturn.json's or the payload_split dev set's.
- Built twice, byte-identical. Full counts: `stats_r8c.json` (SHA-256 `29519a60…62df`), summarised in
  `train/reports/r8c_build_report.json`.

### Holdouts (fresh; scored once, in the R8c holdout stage, by E, E-s2, E-s3 and the three EPL seeds)

| holdout | contents | SHA-256 |
|---|---|---|
| `persona3/holdout/direct/en.jsonl` | 396 benign: enterprise_en 96, arena_en 300 | `07daf55df462dc63468dc06ab3a2caeda5e7a8fef796c37b838e648572dfeadf` |
| `persona3/holdout/direct/vi.jsonl` | 117 benign: enterprise_vi 96, arena_vi 21 | `7dc19996d65e7701cabb7a1b9dd42b3c70f05c98832cf6f8808a92337f7d65dc` |
| `split1/split1.json` | 120 conversations: attack EN 30, VI 30; benign EN 30, VI 30; 2 to 4 user turns | `4090bde0688a7a5e4edde89f6ec7c723c2635af95ee219152ac0fe78750f27a6` |
| `long9` benign (`outputs.long9`) | 49 English documents, 7.30M tokens: docs 9 + 9, rfc 7 + 6, readme 5 + 5, man 4 + 4 at 100k + 200k | `f2ddd0e50a68639ab46d370c744f3e2de41e4a635bde05807dd9ed551d0649f2` |
| `long9` attack | 168 embedded-attack documents and 24 payloads alone (`embed_long.py --eval-payloads 24 --eval-skip 144 --langs en`; eval/ dev-half English rows 144 to 167) | `67f8d299822c28fc33abd1386dc83cbf03b81a02e5b4fc91d3aa6b1c7b55148f` |

- **persona3 enterprise prompts.** 12 new roles per language, 8 prompts each (a third of the Vietnamese ones
  without diacritics). Their openers, rules, tones, refusals and companies are their own: `build_r8c_holdouts`
  refuses any building block that persona1 or R8b (roles B and C) used.
- **persona3 community prompts.** Source: `lmarena-ai/arena-human-preference-140k`, revision `6322995ab34d`. Its
  user prompts are CC-BY-4.0, and the repository uses this source nowhere else. The 7 parquet files are checked
  against their pinned SHA-256s.
  - Rows taken: the first user turn of English and Vietnamese conversations that asks the model to take a role
    or persona (1,009 English, 22 Vietnamese).
  - Rows dropped: by length, by `build_short1.ATTACK_MARKERS`, by overlap with the guarded texts, and as
    near-duplicates. That leaves 929 English and 22 Vietnamese.
  - A seeded 330 English and all 22 Vietnamese went to the label audit: two AI labellers (Claude Sonnet
    subagents), each reading half of the rows in full, before any score.
  - Audit result: English 325 benign, 3 attack, 2 ambiguous; Vietnamese 21 benign, 1 attack. The first 300
    English benign rows in the seeded order are kept (`persona3_audit.json`).
  - The source has 660 Vietnamese conversations and only these 21 persona prompts, so `arena_vi` is reported
    separately and is too small for its own bound.
- **split1.** Written from `data/r8c_templates.py`, never from multiturn.json, the payload_split dev set, eval/
  or train/:
  - Attacks: four intents (override, prompt extraction, jailbreak, exfiltration) and six fragment frames
    (pieces, variables, code concatenation, fill the blank, reversed order, word banks).
  - Benign: string joins in code, sums, word games, "don't ignore the previous instructions", story parts,
    security-awareness questions, SQL and spreadsheet joins, typo corrections and translation fragments.
- **long9.** New `bench/long/corpus.yaml` profile, all sources pinned:
  - docs: VS Code documentation and API (CC-BY-3.0-US), OpenTelemetry documentation (CC-BY-4.0), Traefik v3.7.19
    (MIT);
  - rfc: 82 RFCs;
  - readme: READMEs of OpenTelemetry Collector contrib v0.165.1, AWS CDK library v2.277.0 and TensorFlow Model
    Garden (Apache-2.0);
  - man: Linux man-pages 5.13, sections 2, 3, 4, 5 and 7 (per-page licences).

  `exclude.json` drops 32 units:
  - 28 that share a 50-token run with E's training or validation rows, `persona_neg_train` or the v7 pool;
  - 4 that are 20% near-duplicates of another profile's document.

  Built twice, same SHA-256.

### Overlap and guard checks

- Holdouts against the guarded texts (`build_r8c_holdouts.py check`, `holdout_check.json`): **clean**.
  - Checked: persona3 (513 rows), split1 (459 turns and joined conversations) and long9 (241 documents).
  - Guarded texts: E's 10 training and validation files, `persona_neg_train`, L, S, eval/, persona1 (dev and
    holdout), persona2, the L3 exemplars, multiturn.json, the payload_split dev set and the repository's
    `train/data` rows.
  - Rule for short rows: exact, or half or more of the row's 8-word shingles in the guarded texts. This catches
    every pair with a Jaccard of 0.5 or more.
  - Rule for long9: 50-token runs against the training rows.
- L and S against bench/long and the hold-outs (`build_r8c.py check`, `guard_r8c.json`): **clean**.
  - L: 2,996 of 2,996 rows clean of 50-token runs, 0 with 12-token runs of short hold-out rows, 0 overlaps by the
    8-word rule in either direction.
  - S: 800 of 800 rows clean, with the same zero counts.
  - Index: bench/long quick, full, long, long5 to long9, the R5, long6, long7, long8 and long9 embedded-attack
    documents, and every hold-out row (456M shingles).
- The owner hold-outs (`incoming`, `user_holdout.jsonl`) are never read; the builders refuse such paths. E's files
  are read only for comparison.
- Not fresh: the `eval/data` hold-out half (read since R6), `long5` (dev since R5) and persona2 (read in R8b).

## Measures (ONNX INT8, laptop CPU, gateway path, `main` binaries at the commit of the report)

Every measure is taken for E, E-s2, E-s3 (the E band) and EPL-s1..s3 (the EPL band), reported as min–max.

1. `persona3` (`cmd/eval -path direct`, per language): benign blocked at the shipped threshold, with the
   Clopper-Pearson 95% upper bound; per stratum (enterprise, community EN `arena_en`, community VI `arena_vi`).
2. `eval/data` hold-out half: TPR at FPR ≤ 1%; TPR/FPR at 0.85.
3. `long9` (`cmd/benchlong -long on`, the shipped `long_doc`, each model's own calibration, as R8b's `long5`):
   benign documents blocked; embedded attacks caught; payloads alone caught.
4. `split1`: L2 alone on the conversation window (the user turns joined with a space), no rule layer: TPR of the
   60 attack conversations and FPR of the 60 benign ones at the shipped threshold, per language.
5. Record only (no criterion): `long5` dev and `persona2`, both already read.

## Criteria (each must hold for every EPL seed, that is for the worst EPL seed)

| | criterion | bar |
|---|---|---|
| **C1** | `persona3` benign blocked, per language | ≤ 5%, with the CP95 upper bound reported; the community EN stratum is reported separately and should sit below E's band (aim, not a pass/fail bar) |
| **C2** | `eval/data` hold-out half, TPR at FPR ≤ 1% | ≥ 0.915 (E's lowest seed, R8b) |
| **C3** | `long9` benign documents blocked | ≤ the worst of E's three seeds on `long9` |
| **C3** | `long9` embedded attacks caught | ≥ E's lowest seed on `long9` − 2 points |
| **C4** | `split1`, L2 only | TPR above E's band (higher than E's best seed) and benign FPR ≤ 5% |

## Decision

- If every EPL seed meets C1–C4, EPL becomes the candidate for the next model package (v8f), in shadow mode first;
  the seed to package is the one with the highest C2 among those meeting all criteria. Making it the default stays
  the owner's decision.
- If any EPL seed fails a criterion, the report names the seed and the criterion, and E (v8e) stays the candidate.
- No threshold, rule or calibration is tuned on `persona3`, `long9` or `split1`. Each is scored once per model.

## Limits

- `persona3`'s enterprise prompts are template-generated (12 roles per language), so their CP95 bounds are wide;
  the Vietnamese community stratum is small (see below), so the Vietnamese bound rests mostly on templates.
- `long9` has 49 benign documents of English technical text only (no Vietnamese, no synthetic genres); its
  bar is relative to E's band, not absolute.
- `split1` and `S` are written from templates by the same author, with separate phrase inventories; `split1`
  measures generalisation across phrasings, not across authors.
- Three seeds give the size of the noise, not its distribution.
