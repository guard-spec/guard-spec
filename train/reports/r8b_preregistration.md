# R8b pre-registration: seed noise of arm E, and arm E+P (persona hard negatives) (RF-a957551a)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Written before any R8b training run finished and before `persona2` was scored by anything. The owner chose
option 1 of the R8b spec (seed noise, no arm F) and approved sending E's data, owner rows included, to Colab for
this job; after persona1 (RF-f9d52639) the owner also approved retraining for the Vietnamese persona false
positives, which this round folds in as arm E+P.

## Jobs (Colab L4, one session `r8b`, sequential)

| job | data | seed | purpose |
|---|---|---:|---|
| `E-s2` | E's data (`data-v4A`, `out-full`, `v8e_train.jsonl`), unchanged | 20261106 | seed noise |
| `E-s3` | same | 20261107 | seed noise |
| `EP` | E's data + `persona_neg_train.jsonl` (1,573 benign rows: prompts.chat 1,213; enterprise prompts EN 180, VI 180) | 20261105 (E's) | Vietnamese and English persona false positives |

E itself (seed 20261105, R7) is the first seed. Every model is exported to ONNX INT8 and calibrated with
`cmd/calibrate fit` on the same validation rows as E, then given E's `long_doc` and `l2_untrusted_max` blocks.

## Measures (ONNX INT8, laptop CPU, gateway path, `main` binaries at the commit of the report)

1. **Seed band (E, E-s2, E-s3):**
   - `eval/data` hold-out half: TPR at FPR ≤ 1%, TPR/FPR at 0.85;
   - `long5` dev: benign documents blocked under the shipped `long_doc`, embedded attacks caught.
   - Reported as min–max over the three seeds. No pass/fail: this measures noise.
2. **E+P against E** (pass criteria):
   - **P1.** On `persona2` (fresh; 299 audited prompts.chat rows and 96 enterprise prompts of new roles in EN; 96 in
     VI), E+P blocks at most 5% in each language, with the CP95 upper bound reported.
   - **P2.** On the `eval/data` hold-out half, E+P's TPR at FPR ≤ 1% is not below the lower end of the seed band.
   - **P3.** On `long5` dev, E+P blocks no more benign documents than the worst seed of E and catches no fewer
     embedded attacks than the worst seed minus 2 points.

   persona2 is scored once, for E (shipped v8e) and E+P only.

## Data disclosure

- `persona2` was built by `train/data/build_r8b_persona.py` (seed 20261118):
  - prompts.chat rows outside persona1 and the L3 exemplars, with a seeded 300 held out and label-audited (299
    benign, 1 ambiguous dropped; `persona2_audit.json`);
  - enterprise prompts of 12 new roles per language, written from their own openers, rules, tones and companies, so
    that they share no sentence with the training templates.
- No training row overlaps a persona2 row (exact, or 50% of 8-word shingles), eval/, persona1 or the exemplars.
- SHA-256 of the audited persona2 files: `en.jsonl` `a0d6ea10e102dc2519d60028c38976a170392488ebec202dabb65a07e5dfb951`,
  `vi.jsonl` `e15808b599d94a70863353f602dbcb7fffd770d5e8e8f162fff6f784304c96ab`.
- The eval/data hold-out half is not fresh: it was read in R6–R8a.
- `long5` has been dev since R5.
- No jailbreak set is fresh. JailbreakBench PAIR and TrustAIRLab were spent in persona1, so jailbreak detection
  for E+P is read on eval/data only (P2).

## Decision

- If E+P meets P1–P3, it becomes the candidate for the next model package (v8f), in shadow mode first. Making it
  the default stays the owner's decision.
- If E+P fails, the report says which criterion failed, and E (v8e) stays the candidate.
