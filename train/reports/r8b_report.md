# R8b: seed noise of arm E, and arm E+P (RF-a957551a)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Pre-registration: `train/reports/r8b_preregistration.md` (commit `4580302`). Training ran on Colab L4 on 2026-11-16,
in one session with three jobs, with the owner's approval for E's data, owner rows included:

| job | seed | best epoch | training time |
|---|---:|---:|---:|
| E-s2 | 20261106 | 5 | 45.1 min |
| E-s3 | 20261107 | 5 | 45.1 min |
| EP | 20261105 | 4 | 47.0 min |

- Compute: 382.19 → 377.36 units (4.83).
- The data was deleted from the VM before it was stopped.
- Every model was exported to ONNX INT8 and calibrated on E's 12,785 validation rows. E's `long_doc` and
  `l2_untrusted_max` (0.88) were added.
- Measures: laptop CPU (Apple M3 Max), binaries from `main` at `c1005a5` plus this branch's training changes, which
  do not touch the gateway.

## Seed noise of arm E (same data, same recipe, three seeds)

| measure | E (v8e, seed 20261105) | E-s2 | E-s3 | band |
|---|---:|---:|---:|---|
| eval/data hold-out, AUC | 0.989 | 0.987 | 0.988 | 0.987–0.989 |
| eval/data hold-out, TPR at FPR ≤ 1% | **0.960** | 0.915 | 0.925 | **0.915–0.960** |
| eval/data hold-out, TPR / FPR at 0.85 | 0.937 / 0.0% | 0.932 / 2.0% | 0.952 / 2.0% | FPR 0–2.0% |
| long5 dev, benign blocked (150) | 0 | 0 | 1 | 0–1 |
| long5 dev, embedded attacks caught (560) | 487 | 466 | 484 | 466–487 (83.2–87.0%) |
| long5 dev, payloads alone (80) | 75 | 75 | 75 | — |

E's numbers are from this commit's binaries:
- eval/data was measured again here;
- for long5, E's run is the one in `indirect1_holdout.md` (same long-path code: the untrusted L1 floor, the `ei.*`
  rules, and the shipped `long_doc`).

**Reading.**
- Changing only the seed moves the hold-out TPR at FPR ≤ 1% by 4.5 points, FPR at 0.85 by 2 points, and long5
  embedded detection by 3.8 points.
- E, the shipped v8e, is the best of its three seeds on most measures.
- Several arm comparisons in R6–R8a were decided by gaps of this size or smaller, from one seed each. They were
  within the noise, and later rounds should compare bands, not single runs.

## Arm E+P against the pre-registered criteria

| criterion | bar | E+P | result |
|---|---|---|---|
| P1, persona2 benign blocked (scored once) | ≤ 5% per language | EN **0.5%** (2/395, CP95 upper 1.8%); VI **0%** (0/96, CP95 upper 3.8%) | **met** |
| P2, eval/data hold-out TPR at FPR ≤ 1% | ≥ 0.915 (lowest seed) | **0.949** | **met** |
| P3, long5 benign blocked | ≤ 1 (worst seed) | **4** of 150 | **not met** |
| P3, long5 embedded caught | ≥ 466 − 11 = 455 | **493** of 560 (88.0%) | met |

**Verdict: E+P is not met (P3, benign long documents).** Under the pre-registration, E (v8e) stays the candidate.

On persona2, E itself blocks 3.3% EN (13/395; prompts.chat 4.3%) and 0% VI. E+P removes most of these blocks.

## What E+P blocks on long5

All four blocks are English technical documents in the holdout half of long5:

| document | genre | doc score |
|---|---|---:|
| `long5-docs-en-200000-0` | docs | 0.990 |
| `long5-rfc-en-100000-2` | rfc | 0.969 |
| `long5-docs-en-100000-3` | docs | 0.966 |
| `long5-docs-en-100000-0` | docs | 0.954 |

None of E's three seeds blocks them. The 1,213 prompts.chat rows added as benign are long instruction texts, so a
plausible reading is this: the model learnt that instruction-shaped prose sent as a *prompt* is benign, and its
calibration shifted, which raised windows of imperative technical documentation over the long-path bar. This is a
reading, not a measured cause.

## What this means

- **The persona fix works at the classifier level, but it trades against long documents.** A next attempt should add
  benign long technical windows next to the persona rows. Its acceptance should be judged against the seed band, not
  against E's single run.
- **v8e as the default.** E clears persona2 for Vietnamese (0%) and is at 3.3% for English, under 5%.
  - It had already cleared long8 (R8a).
  - With the untrusted L1 floor (RF-67fdf675), it catches 72.3% of indirect1's email injections.
  - The remaining reason not to switch is short1's C3 EN, on in-the-wild community role-play, which persona1 showed
    is mostly not enterprise traffic.
  - Whether to make v8e the default is the owner's decision.

## Limits

- Three seeds is a small sample for a band. It shows the size of the noise, not its distribution.
- persona2's enterprise prompts are template-generated (12 roles per language), so their CP95 bounds are wide.
- long5 has been dev since R5, and the eval/data hold-out half has been read since R6.
