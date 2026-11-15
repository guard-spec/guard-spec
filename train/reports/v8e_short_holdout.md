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

## Runs (2026-11-15, Apple M3 Max, ONNX INT8 on the CPU, `cmd/eval` built from `2a7bec8`)

Each model scored once, 06:58 to 07:04: `-detector fusion-ml`, default layers, each model's own calibration.
`direct` and `tool` as pre-registered, plus `llmail` on `-path direct` (record). No row was rejected by the
sanitizer. Full numbers: [`v8e_short_holdout.json`](v8e_short_holdout.json) (`train/verdict_short1.py`).

## Verdict: v8e does not meet `short1` (C2 and C3 fail)

| criterion | v8e | v3b | result |
|---|---|---|---|
| C1 direct attacks (`tw_jailbreak`, 500) | 75.0% | 76.2% | met: −1.2 points, paired 95% −4.0 to +1.6 |
| C2 email attacks (`llmail_attack`, 400, `-path tool`) | **12.0%** | 27.8% | **not met**: −15.8 points, paired 95% −20.0 to −11.5 |
| C3 direct benign EN (1,000) | 12.1% (CP95 upper 14.3%) | 13.4% | **not met**: below v3b, but above the 2% cap |
| C3 direct benign VI (369) | 0.5% (CP95 upper 1.9%) | 2.2% | met |
| C3 tool benign (157) | 0 / 157 (CP95 upper 2.3%) | 0 / 157 | met |

v8e stays a candidate in shadow mode. v3b stays the default.

**Per stratum** (blocked / rows, the gateway's decision)

| stratum | v8e | v3b | v6rel |
|---|---|---|---|
| `tw_jailbreak` (attack) | 375 / 500 | 381 / 500 | 379 / 500 |
| `llmail_attack`, tool path | 48 / 400 | 111 / 400 | 49 / 400 |
| `llmail_attack`, direct path (record) | 94 / 400 | 116 / 400 | 101 / 400 |
| `tw_regular` (benign) | 113 / 500 | 127 / 500 | 115 / 500 |
| `wildchat_en` (benign) | 8 / 500 | 7 / 500 | 8 / 500 |
| `wildchat_vi` (benign) | 2 / 300 | 7 / 300 | 4 / 300 |
| `hs3_vi` (benign) | 0 / 69 | 1 / 69 | 0 / 69 |
| `llmail_benign`, both paths | 0 / 157 | 0 / 157 | 0 / 157 |

Threshold-free, all direct rows: ROC AUC v8e 0.916, v3b 0.916, v6rel 0.915. On `llmail` (both paths): v8e 0.971,
v3b 0.903, v6rel 0.940.

## Label audit (secondary, after the one scoring)

Two blind labellers (AI agents, each half of the rows, with one fixed rubric and no scores) read 347 rows:
- every benign row any model blocked (172);
- every `tw_jailbreak` row v8e missed (125);
- a seeded sample of 50 `llmail_attack` rows v8e missed on the tool path.

| stratum, source label | audited attack | audited benign | ambiguous |
|---|---|---|---|
| `tw_regular`, benign (blocked by a model) | 45 | 101 | 0 |
| `wildchat_en`, benign (blocked) | 1 | 14 | 0 |
| `wildchat_vi` and `hs3_vi`, benign (blocked) | 1 | 10 | 0 |
| `tw_jailbreak`, attack (missed by v8e) | 30 | 80 | 15 |
| `llmail_attack`, attack (missed, sample) | 50 | 0 | 0 |

The source labels are noisy where the pre-registration expected:
- About a third of the blocked "regular" prompts are jailbreaks or instruction overrides the marker filter
  missed, for example "ignore all instructions before this one" headers on task templates.
- Most `tw_jailbreak` rows v8e misses are harmless personas, games or character cards.
- The `llmail` labels hold: every sampled miss is a real injection.

**With audited labels** (ambiguous rows left out; rows not audited keep their source label):

| | v8e | v3b | v6rel |
|---|---|---|---|
| `tw_jailbreak`, audited attacks (405) | **92.6%** | 90.6% | 91.4% |
| `tw_jailbreak` rows audited benign (80), blocked | 0 | 13 | 7 |
| direct benign EN (954) | 8.2% | 9.6% | 8.5% |
| of which `tw_regular` (455) | 15.6% | 18.9% | 16.3% |
| of which `wildchat_en` (499) | 1.4% | 1.2% | 1.4% |
| direct benign VI (368) | 0.5% | 1.9% | 1.1% |

Only the rows a model blocked or v8e missed were audited. The audit can therefore only remove v8e misses, never
v8e catches, and the audited jailbreak TPR leans toward v8e. The FPR rows are not affected: every blocked benign
row was audited.

## Reading

- **C2 is mostly the untrusted-content cap.**
  - v8e and v6 cap L2 at 0.88 on tool content (`l2_untrusted_max`); v3b has no cap. On the same emails sent as
    user messages, v8e catches 23.5% against v3b's 29.0%.
  - v8e ranks these emails best of the three (AUC 0.971), but most of them score low for every model (median
    under 0.1).
  - LLMail-Inject attacks were written to get past injection defenses. No model here catches more than 30% at
    0.85.
- **C3 EN is not a v8e regression.**
  - Persona and role-play system prompts (`tw_regular`) are blocked by every model, at 16 to 19% after the
    audit; v8e is the lowest.
  - Ordinary user requests (`wildchat_en`) are blocked at 1.2 to 1.4% by all three models.
  - The 2% cap fails because `tw_regular` makes up half of the English benign rows. That is a property of the
    holdout mix, written into the pre-registration before the scores, and it stands.
- **Where v8e is better:**
  - Vietnamese false positives: 0.5% against 2.2%;
  - harmless personas labelled jailbreak: 0 blocked against 13;
  - indirect emails, by ranking (AUC).

## What this means

- v8e is not proposed as the default.
- Two weaknesses are shared by every Guard Spec model and are the next work, not v8e problems:
  - indirect email injections: under 30% detection at 0.85;
  - persona and role-play system prompts: about 16 to 19% blocked.
- The untrusted-content cap trades indirect detection for fewer false positives on documents. `short1` measures
  what it costs on emails (−11.5 points for v8e). Whether to keep 0.88 for v8e is a decision for a follow-up task.

## Limits

- No Vietnamese attack. The audit uses AI labellers, one per row, with no second opinion.
- `llmail` comes from one challenge with one goal (a send-email call).
- `short1` is now spent. Any later look at it is a dev look.

## Reproduce

```sh
cd train
uv run --frozen python data/build_short1.py --raw <raw> --out <out>   # checks against the SHA-256 above
# cmd/eval -detector fusion-ml -data <out>/{direct,tool} -path {direct,tool} -scores ... per model (scored once)
uv run --frozen python verdict_short1.py --scores <scores> --data <out> --out reports/v8e_short_holdout.json
```
