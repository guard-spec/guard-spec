# v8e short-prompt pre-registration: `short1`, a fresh short-prompt holdout, v8e against v3b (RF-b15702bf)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written on 2026-11-15, before `short1` is built and before any model scores a row of it. The source files were
downloaded and their structure (columns, row counts per language and label) was read to set the sample sizes
below. No row was scored and no model was loaded. `train/data/build_short1.py` implements the rules here, and
its constants are the values in this file. Nothing is trained, and no owner row is used except as a
deduplication key on the laptop.

## Problem

v8e (R7's arm E, `train/hf/v8e`) is a candidate in shadow mode. Every short-prompt number for it comes from the
eval/data hold-out half, which was read for `ref`, B, C, D and E in R6 to R8a and is not fresh. eval/data dev
has been the selection target since v3. Before v8e can be proposed as the default classifier (v3b today), it
needs a short-prompt measure on text that no earlier round selected on.

**Question.** On fresh, real-world short prompts and emails, does v8e keep v3b's attack detection without more
false positives, through the gateway's decision?

## Models (fixed, each scored once on `short1`)

| name | role | files | `model_int8.onnx` SHA-256 |
|---|---|---|---|
| **v8e** | candidate | `guardspec-data/v8/v8e/pkg` (the package in `train/hf/v8e`, `calibration.json` `3419798d…5da6`) | `447c63cd6f2378c957b3282a1d4526f00feef9153e0046203c10fb20d75d7dde` |
| **v3b** | comparator (the default) | `models/local/guardspec-classifier-v3b` | `87368d45526ae4f3a1830231d9187814577568e894246a284c8689a9a6cc6ae3` |
| v6rel | record only | `guardspec-data/v6/release/guardspec-classifier-v6` | `be5fba5b2c94fdbb20a628002cadde2857349dbb6092e3690ba41d6bcd347f29` |

Every number is ONNX INT8 on the laptop's CPU. `cmd/eval` is built once, from the commit that pins `short1`, and
run with `-detector fusion-ml`, the default layers (L1, L2, L3) and logreg fusion, as R7's gates. Each model's own
`calibration.json` is used. Short prompts are at most 30 windows, so `long_doc` does not apply.

## Holdout: `short1`

**Sources.** None of them was used in any training, validation, evaluation or benchmark set of Guard Spec.
Licenses were checked on each card at the pinned revision.

| stratum | source (revision) | license | label | path | up to |
|---|---|---|---|---|---|
| `tw_jailbreak` | `TrustAIRLab/in-the-wild-jailbreak-prompts` `jailbreak_2023_12_25` (`a10aab8e`) | MIT | attack (jailbreak) | direct | 500 |
| `tw_regular` | same, `regular_2023_12_25`, rows with `jailbreak` false | MIT | benign | direct | 500 |
| `wildchat_en` | `allenai/WildChat-1M` shard 00 (`7d6490e4`), first user turn, English | ODC-BY | benign | direct | 500 |
| `wildchat_vi` | same, shards 00 and 01, Vietnamese | ODC-BY | benign | direct | 300 |
| `hs3_vi` | `nvidia/HelpSteer3` `preference` train and validation (`f6d14577`), first user turn, Vietnamese | CC-BY-4.0 | benign | direct | 300 |
| `llmail_attack` | `microsoft/llmail-inject-challenge` phase 2 unique submissions (`1063bdf0`), `attack_attempt` True and `reason` `api_triggered` | MIT | attack (indirect) | tool | 400 |
| `llmail_benign` | same, `emails_for_fp_tests.json` | MIT | benign | tool | 300 |

- `api_triggered` means the email made the challenge's LLM call the send-email tool, so the attack label does not
  rest on a judge.
- WildChat rows flagged `toxic` or `redacted` are dropped. English comes from shard 00 only.
- From the structure read: `hs3_vi` has 194 candidate rows and `llmail_benign` 203, so both keep all their rows
  that pass the filters. `wildchat_vi` has 464 candidates.

**Filters, in this order, per stratum**
1. Length: 20 to 6,000 characters after trimming.
2. `tw_*` only: at least 90% of letters are Latin script (drops the Chinese and other prompts in that set).
3. Benign strata only: rows that match the fixed `ATTACK_MARKERS` pattern in the script (for example "ignore
   previous instructions", "DAN", "developer mode", "jailbreak", "system prompt", "bỏ qua mọi hướng dẫn") are
   dropped. WildChat and the "regular" set contain some attack attempts. The counts are reported.
4. Prior overlap: rows whose normalized text equals a prior row, or whose 8-word shingles are 50% or more in the
   prior index, are dropped. The prior index is every row of:
   - eval/data;
   - `train/data`;
   - every v3b, v4-A, v5, v6, v7 and v8 training and validation file under `guardspec-data`;
   - the owner's processed files (as keys only);
   - the public benchmark test splits (deepset, jackhhao test and train, Gandalf, SPML).
5. Sampling: rows are ordered by SHA-256 of `20261115:<text>`. They are taken in that order up to the stratum's
   size, skipping near-duplicates of a row already kept (Jaccard of 8-word shingles ≥ 0.7). Strata are filled in
   the table's order.

Expected size: about 900 attacks (500 direct, 400 tool) and about 1,700 benign rows (about 1,000 English and
about 500 Vietnamese direct, about 200 tool).

`short1` has **no Vietnamese attack**. We found no public, licensed Vietnamese prompt-injection set. Vietnamese is
measured for false positives only, and the report says so.

`build_report.json` (the counts after each filter) and the SHA-256 of each output file are committed into this
file's companion, `v8e_short_holdout.md`, in a commit made before any score.

## Criteria (v8e against v3b, the gateway's decision, `gateway_rule` of `cmd/eval`)

- **C1, direct attacks** (`tw_jailbreak`):
  - TPR(v8e) ≥ TPR(v3b) − 2 points; and
  - the lower end of the paired bootstrap 95% interval of TPR(v8e) − TPR(v3b) is ≥ −5 points (10,000 resamples
    of rows, seed 20261115).
- **C2, indirect attacks** (`llmail_attack`, `-path tool`): as C1.
- **C3, false positives.** For each group (direct English, direct Vietnamese, tool):
  - FPR(v8e) ≤ FPR(v3b) + 0.5 point; and
  - the two-sided Clopper–Pearson 95% upper bound of FPR(v8e) is ≤ 2% for direct English and Vietnamese, and
    ≤ 3% for tool.

**Verdict.** v8e meets `short1` if C1, C2 and C3 all hold. Then a follow-up proposes v8e as the default, and the
owner decides. Otherwise v8e stays a candidate in shadow mode, and the report says which criterion failed.

**Reported, not criteria:**
- TPR at FPR ≤ 1% and ROC AUC on all direct rows;
- the numbers per stratum;
- v6rel;
- `llmail_attack` on `-path direct` (the same text sent as a user message).

**Label audit (secondary).** After the one scoring, the benign rows any model blocks and the attack rows v8e
misses are read and classed as mislabelled or correctly labelled. The audited numbers are reported next to the
raw ones. The verdict uses the raw labels.

## Disclosure

- The sources were picked after looking at public dataset cards. The sample sizes were set after reading each
  file's row counts per language and label, not texts or scores.
- The labels come from their sources:
  - TrustAIRLab's jailbreak label comes from the communities that shared the prompts;
  - WildChat, HelpSteer3 and the "regular" prompts are taken as benign after the marker filter.

  Some label noise remains, and the audit measures it.
- Many `tw_regular` prompts are role-play or persona system prompts. They are hard negatives, the kind that
  v8's pairing was suspected of over-blocking in R8a's dev checks.
- `llmail_attack` texts come from one challenge with fixed goals (a send-email call to `contact@contact.com`).
  They are not a sample of all indirect attacks.

## Implementation commitment

- `short1` is scored once per model. Any later look at it is a dev look and is labelled so.
- Nothing is packaged, published, tagged or uploaded by this step. `models/manifest.yaml` and the default model
  are unchanged.
