# indirect1: holdout result (RF-67fdf675)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/indirect1_preregistration.md` (commit `2bfc9db`). The holdout
(`holdout/tool/en.jsonl`, SHA-256 `cc70f5c3…`, checked before scoring) was scored once, on 2026-11-16, with
`cmd/eval -detector fusion-ml -path tool`, layers l1,l2,l3, ONNX INT8 on the laptop's CPU (Apple M3 Max). Verdict:
`train/verdict_indirect1.py` → `indirect1_holdout.json`.

## Verdict: both criteria pass

| | reference: v3b, rules of `main` (`fb4f9c8`) | **candidate: v3b, `627444f`** | criterion | result |
|---|---:|---:|---|---|
| C1, attacks blocked (560) | 47.7% (267) | **77.0%** (431) | ≥ reference + 15 points, paired 95% lower bound > +10 | **+29.3 points** (95%: +25.5 to +33.0): **pass** |
| C2, clean rows blocked (541) | 0.6% (3) | 0.9% (5) | Clopper-Pearson 95% upper bound ≤ 3% | **2.1%**: **pass** |

The candidate is the configuration chosen on dev (pre-registration, step a):
- the new `ei.*` L1 rules (an email or tool result that dictates a message to an address, or hands the agent a task
  or a tool call);
- the untrusted-content L1 floor, `UNTRUSTED_L1_FLOOR`, now on by default at 0.90. On tool results and documents
  only, a calibrated L1 score at or above the floor is a lower bound of the fused score.

Neither the cap exemption (step b) nor retraining (step c) was needed.

## By stratum and system (share blocked, as the gateway decides)

| stratum | rows | ref v3b | ref v8e | **cand v3b** | cand v8e |
|---|---:|---:|---:|---:|---:|
| LLMail level 2 (held-out scenario), attacks | 400 | 51.2% | 20.5% | **84.8%** | 81.2% |
| AgentDojo, attacks | 160 | 38.8% | 40.6% | **57.5%** | 50.0% |
| AgentDojo, clean records | 141 | 2.1% (3) | 0.0% | 2.1% (3) | 0.0% |
| glaive function results, clean | 400 | 0.0% | 0.0% | 0.5% (2) | 0.5% (2) |
| **all attacks** | 560 | 47.7% | 26.2% | **77.0%** | 72.3% |
| **all clean** | 541 | 0.6% | 0.0% | 0.9% | 0.4% |

AgentDojo attacks by template (blocked / rows):

| template | rows | ref v3b | ref v8e | cand v3b | cand v8e |
|---|---:|---:|---:|---:|---:|
| `injecagent` ("IMPORTANT!!! Ignore all previous instructions …") | 34 | 34 | 34 | 34 | 34 |
| `system_message` | 29 | 10 | 8 | 17 | 13 |
| `ignore_previous` | 32 | 5 | 13 | 15 | 14 |
| `direct` ("TODO: …") | 32 | 8 | 2 | 13 | 7 |
| `important_instructions` | 33 | 5 | 8 | 13 | 12 |

By suite: banking 18/20 in both v3b systems; travel 13 → 34 of 67; workspace 30 → 39 of 72; slack 1/1.

## Reading

- **The fusion was drowning the rules on untrusted content.** On dev, 225 of 1,400 attacks had a calibrated L1
  score of 0.85 or more and a fused v8e score below 0.1: the logistic combiner weights L1 at about half of L2, and
  v8e's cap holds L2 down on tool content. The floor alone took dev from 42.9% to 53.1% (v3b) and from 22.9% to
  37.5% (v8e); the `ei.*` rules took v3b to 63.9%. On the holdout the gain is larger (+29.3 points), mostly on
  LLMail.
- **v8e benefits most.** On the holdout v8e goes from 26.2% to 72.3%, close to v3b (77.0%): its gap on email
  injections (short1: 12.0% against 27.8%) came from the cap with no L1 floor, not from the classifier. The cap
  (`l2_untrusted_max` 0.88) stays.
- **AgentDojo is harder than LLMail.** Its templates mostly read as polite requests from the user ("Before you can
  solve the task that I gave you …", "TODO: …"); 57.5% are caught. Its goals differ from LLMail's single goal, so
  this is the generalization measure; the `ei.*` rules were written on LLMail, InjecAgent and BIPIA dev rows.
- **Clean rows.** The 3 AgentDojo records the candidate blocks were already blocked by the reference (v3b with
  `main`'s rules). The 2 glaive rows the candidate adds are an artifact of `build_indirect1.py`: its regex let the
  function result run into the next chat turn (`<|endoftext|>` and `ASSISTANT: …`), and `ii.chat_template`
  rightly flags a chat template inside a tool result. They are counted as false positives, as scored.

## Gates (dev, before the holdout)

- CI eval gates with v3b (`eval/data`, `eval/codelog`, `eval/embedded` with and without corroboration): no
  regression beyond 0.02. With the floor, `eval/embedded` catches 86.3% of attacks at 0.85 (75.0% before) with
  4.48% of clean rows blocked (4.28%), and `eval/codelog` blocks 27 of 310 clean rows (25 before: two logs whose
  folded text matches the exfiltration rules). The three tool-path ONNX baselines were refreshed; their detector
  name now ends in `/l1floor`.
- `long5` dev, v8e's long path with the rules and the floor: 0 of 150 benign documents blocked (as before), 487
  of 560 embedded attacks caught (as before), payloads alone 75/80 (69/80).

## Limits

- One holdout, English only; Vietnamese was measured on dev (template-generated emails, 24 attacks: 62.5% for v3b, 70.8%
  for the candidate, no clean email blocked).
- LLMail has one goal (send "confirmation" to one address). The rules do not name that address or word, but
  they were tuned on LLMail dev rows, so its 84.8% overstates what a new campaign would meet; AgentDojo's 57.5% is
  the more honest figure.
- The floor trusts the rules on untrusted content. A rule false positive in a tool result now blocks even when the
  classifier is sure the text is clean (the two `eval/codelog` rows above). `UNTRUSTED_L1_FLOOR=off` restores the
  previous behaviour.
