# FP16 vs INT8, guardspec-classifier-v8e (RF-b15702bf)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

Measured on 2026-11-15 on the CPU (Apple M3 Max). These numbers compare the two model files, not the GPU. CUDA
against the CPU on the same FP16 file, and FP16 on the long path, are the GPU measurement of RF-b15702bf.

## Files

| file | SHA-256 | origin |
|---|---|---|
| `model_int8.onnx` | `447c63cd…` | R7 arm E, as scored in R7 and R8a |
| `model_fp16.onnx` | `601bdd4d1c1ae3666acb509445e870fb51bd0c30f6a35ff344f417c5e2dbb4ce` | `train/export.py --fp16 --fp32 <run>/model_fp32.onnx` |

The FP16 file is checked against FP32 on 1,024 validation windows:
- FP16 vs FP32: max |Δp| 0.0028, mean 1.1e-5;
- torch vs the FP16 file: max 0.0028.

## Calibration

`cmd/calibrate fit` ran on the 12,785 validation rows that calibrated E. These rows stayed on the laptop.

- **Check of the procedure.** Refitting the INT8 file gives E's shipped values exactly: Platt A 0.8293, B −0.3497;
  `l1,l2` (0.4440, 0.9430), bias 0.3805.
- **FP16 block** (`calibration.json` → `fp16`):
  - Platt A 0.8422, B −0.6727;
  - `l1,l2` weights (0.4518, 0.9425), bias 0.3760;
  - `l1,l2,l3` weights (0.4380, 0.9164, 0.2738), bias 0.4847;
  - `l2_untrusted_max` 0.88.
- **Out of fold, L2 alone:** FP16 AUC 0.9984, TPR at FPR ≤ 1% 0.9865.
- **Long-path rule.** The block has no `long_doc` of its own, so it takes the top-level rule (`ml.forModelFile`,
  commit `560421f`).

## Agreement at 0.85 (fused `l1,l2,l3`, `cmd/eval -scores`, each model with its own calibration)

| set | rows | agreement | differ | max \|Δscore\| | mean \|Δscore\| |
|---|---:|---:|---:|---:|---:|
| `eval/data` (en, vi, both halves) | 2,176 | 99.13% | 19 | 0.61 | 0.0084 |
| `val_v3` | 508 | 99.80% | 1 | 0.41 | 0.0066 |

## Accuracy (eval/data, all rows; reporting only, nothing was fitted on it)

| model | AUC | TPR at FPR ≤ 1% | TPR / FPR at 0.85 |
|---|---:|---:|---:|
| INT8 | 0.987 | 0.952 | 0.929 / 0.20% (2 of 1,005) |
| FP16 | 0.990 | 0.951 | 0.937 / 0.40% (4 of 1,005) |

On the hold-out half, at 0.85, TPR / FPR is 0.937 / 0.0% for INT8 and 0.942 / 0.2% for FP16.

## Reading

- FP16 is the closer copy of the FP32 model. As for v6, about 1% of decisions near the threshold differ between a
  GPU and a CPU gateway.
- At 0.85, FP16 catches a little more and blocks two more benign rows.
- R8a's dev check showed that FP32 blocks more benign long documents than INT8 under `strong75_l2` (2 of 41 `long5`
  documents against 0). FP16 is close to FP32, so the long path in FP16 needs its own measurement before the GPU
  option is recommended for v8e.
