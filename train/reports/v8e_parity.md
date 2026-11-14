# v8e parity: the gateway's long-document rule against the R8a decision (RF-b15702bf)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

The gateway now carries the R8a decision `strong75_l2` as two `long_doc` options in `calibration.json`
(`corroborate_l1` 0.75, `min_l2` 0.95, commit `fac5610`). This check shows that the gateway's long path with
those options blocks exactly the documents `train/longdoc_r8a.py` blocks.

## Setup

- Model: R7's arm E (`model_int8.onnx` SHA-256 `447c63cd…`). The calibration is E's own, with this added:
  `"long_doc": {"min_windows": 30, "corroborate_l1": 0.75, "min_l2": 0.95, "base": 0.85}`.
- Data: `long5`, both halves (dev since R5, 150 benign documents), and the R5 attack documents (640). No
  holdout was opened. `long6`, `long7` and `long8` are spent.
- Run: `cmd/benchlong -long on -layers none -l2pass off -dump`, built from `fac5610`, ONNX INT8 on the laptop's
  CPU, on 2026-11-15 from 00:41 to 02:46.
- Reference: `longdoc_r8a.hits("strong75_l2")` on R7's `long5` dumps of E, the dumps R8a's dev table used.
- The gateway blocks a document when its `doc_score` (the long path's score under the rule) is at least 0.85.

## Result: identical

| | documents | same decision | different | windows with a different score |
|---|---|---|---|---|
| benign | 150 | 150 | 0 | 0 documents |
| attack (embedded, alone, other variants) | 640 | 640 | 0 | 0 documents |

- Benign documents blocked: **0 / 150** on both sides.
- Embedded attacks caught: **481 / 554** (86.8%) on both sides. The payloads alone: **69 / 80** (86.3%).
- Both match R8a's dev table in `r8a_preregistration.md`.
- Every window's score before the rule matches R7's dump within 1e-5, so the only change is the rule itself.

`internal/inference/ml/longdoc_test.go` (`TestLongDocRuleStrong75L2`) checks the same equivalence window by
window, over a grid of (score, L1, L2, floor) values.

## Reproduce

```sh
# model dir: E's files + calibration.json with the long_doc above (guardspec-data/v8/v8e/E_l2, not in git)
L2_MODEL_DIR=.../E_l2 benchlong -corpus .../corpora/long5 -profile v8e-parity-benign -layers none -l2pass off \
  -long on -dump .../parity/benign -skip-latency -workers 4 -out .../parity/benign.json
# the same for corpora/long5-attack, then compare doc_score >= 0.85 with longdoc_r8a.hits per document
```
