# v8e short-prompt holdout `short1`: v8e against v3b, scored once (RF-b15702bf)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Follows [`v8e_short_preregistration.md`](v8e_short_preregistration.md) (commit `69a3ebd`).

## Build (pinned before any score)

Built on 2026-11-15 by `train/data/build_short1.py` (seed 20261115). Counts after each filter, in the order the
filters run:

| stratum | candidates | length | not Latin | attack marker | prior exact | prior overlap | near-duplicate | **kept** |
|---|---|---|---|---|---|---|---|---|
| `tw_jailbreak` | 1,405 | 98 | 2 | – | 588 | 142 | 18 | **500** |
| `tw_regular` | 13,735 | 755 | 169 | 1,737 | 27 | 133 | 18 | **500** |
| `wildchat_en` | 29,242 | 2,828 | – | 1,705 | 13 | 31 | 87 | **500** |
| `wildchat_vi` | 461 | 64 | – | 0 | 0 | 0 | 28 | **300** |
| `hs3_vi` | 194 | 19 | – | 0 | 0 | 0 | 106 | **69** |
| `llmail_attack` | 3,165 | 22 | – | – | 0 | 1 | 166 | **400** |
| `llmail_benign` | 203 | 0 | – | 0 | 0 | 0 | 46 | **157** |

- 588 of TrustAIRLab's jailbreak prompts are exact copies of prior rows, mostly jackhhao's set, which took its
  prompts from the same websites.
- `hs3_vi` keeps 69 rows, because HelpSteer3 repeats a first turn across several preference rows.
- In all: 900 attacks (500 direct, 400 tool) and 1,526 benign rows (1,000 direct English, 369 direct
  Vietnamese, 157 tool).

| file | rows | SHA-256 |
|---|---|---|
| `direct/en.jsonl` | 1,500 | `c4bf34fa82a72ac55c3b4b7cf49cea8daf2da5709bf13d0b2d209d7b33e1dd42` |
| `direct/vi.jsonl` | 369 | `31ccface4320d943ba48cd860d20a54bccd0794f736520980a73b9744f2ee63a` |
| `tool/en.jsonl` | 557 | `92d72260d124ab61b89d4f9f5bace6600c7747cbb04bf67a0ac27aa65a93d577` |

The files stay outside the repository (`guardspec-data/v8/v8e/short1/out`), with `build_report.json` (raw-file
SHA-256 values and the prior-index file list).

## Results

Pending: each model is scored once after this commit.
