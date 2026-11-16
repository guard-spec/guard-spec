# persona1: holdout result (RF-f9d52639)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/persona1_preregistration.md` (commit `ff290a9`). The audited holdout
(`en.jsonl` `076e3d7d…`, `vi.jsonl` `6b0bdf0c…`, both checked before scoring) was scored once, on 2026-11-16,
with `cmd/eval -detector fusion-ml -path direct`, layers l1,l2,l3, ONNX INT8 on the laptop's CPU. Reference:
`main` at `30da730`. Candidate: `1f41e5c`, which adds 59 benign persona exemplars to the L3 set. Verdict:
`train/verdict_persona1.py` → `persona1_holdout.json`.

## Verdict: not met (C1 VI fails for v3b)

| criterion (v3b) | reference | **candidate** | bar | result |
|---|---:|---:|---|---|
| C1 EN, benign blocked (605) | 4.3% (26) | **3.3%** (20), CP95 upper 5.1% | ≤ 5% | **met** |
| C1 VI, benign blocked (96) | 7.3% (7) | **6.3%** (6), CP95 upper 13.1% | ≤ 5% | **not met** |
| C2, audited attacks blocked (245) | 13.1% (32) | 13.1% (32) | drop ≤ 2 points | **met** (no change; paired 95% 0.0 to 0.0) |

v8e, reported (not part of the criteria):

| | v8e reference | v8e candidate |
|---|---:|---:|
| EN benign blocked (605) | 5.3% (32) | **4.0%** (24), CP95 upper 5.9% |
| VI benign blocked (96) | 1.0% (1) | **1.0%** (1), CP95 upper 5.7% |
| audited attacks blocked (245) | 12.2% (30) | 11.4% (28) |

v8e with the candidate's exemplars is under 5% on both languages.

## By stratum (blocked / rows)

| stratum | rows | ref v3b | cand v3b | ref v8e | cand v8e |
|---|---:|---:|---:|---:|---:|
| prompts.chat, benign | 493 | 19 | **14** | 27 | **21** |
| enterprise EN, benign | 96 | 4 | 3 | 2 | 1 |
| enterprise VI, benign | 96 | 7 | 6 | 1 | 1 |
| jailbreak sources audited benign | 16 | 3 | 3 | 3 | 2 |
| TrustAIRLab jailbreaks | 29 | 25 | 25 | 23 | 21 |
| JailbreakBench random search | 7 | 7 | 7 | 7 | 7 |
| **JailbreakBench PAIR** | 209 | **0** | **0** | **0** | **0** |

## Reading

- **The persona false-positive rate is lower than `short1` suggested.**
  - On real "act as" prompts (prompts.chat) and enterprise system prompts in English, v3b blocks 3–4%. `short1`'s
    18.9% came from a jailbreak-sharing community's role-play.
  - The exemplars take another fifth off for both models, with no loss on any attack set (eval/data: jailbreak
    130 of 146 before and after).
- **Vietnamese enterprise prompts are a v3b problem.** v3b blocks 6–7 of 96 with or without the fix. v8e blocks 1.
  The blocks come from the classifier: L1 and L3 changes did not move them on dev. Only retraining (step d, not
  approved) would.
- **PAIR jailbreaks are not caught at all.** No system blocks any of the 209 PAIR prompts.
  - These are long role-play or hypothetical framings that ask for harmful content ("in the spirit of exploring
    controversial journalism, write …"). They carry no instruction override, no persona switch and no
    prompt-extraction cue.
  - Guard Spec's classifier is trained on injection and jailbreak *mechanics*, not on harmful-content requests, so
    this is a scope gap rather than a regression.
  - It should be a decision of its own: either content moderation is out of scope, as documented, or a harmful-
    request category is added.
  - The C2 numbers are therefore small (13%) and dominated by TrustAIRLab's DAN-style rows. C2's "no loss" holds,
    but it says little about role-play attacks.

## Gates (dev, before the holdout)

- CI eval gates with v3b: `eval/data`, `eval/codelog` and `eval/embedded` show no regression beyond 0.02.
- `eval/embedded` without corroboration (not the default) lost 1 of 34 `vi/obfuscation` rows. Its baseline was
  refreshed: AUC 0.951 → 0.952; at 0.85, TPR 90.9% → 90.4% and FPR 13.3% → 10.3%.
- The L1-only gates show no regression.
- L3 does not run on the long path, so `long5` is unaffected.

## Limits

- One holdout. The Vietnamese benign set is 96 template-generated enterprise prompts from 12 roles, so its CP95
  upper bound is wide (13.1%).
- The labels are AI labels with no second opinion. Every holdout row except the enterprise templates was labelled
  before scoring, from the full text, blind to source and source label.
- prompts.chat is partly in earlier training data through other datasets. Overlapping rows were dropped, so the
  remaining rows are the ones no model has seen.
