# FP16 vs INT8 decision agreement, guardspec-classifier-v6

Task RF-b74de2b9 (GPU option), todo G2, 2026-11-12. All runs were on the CPU
(Apple M3 Max, ONNX Runtime 1.31.1), so these numbers measure the model files,
not the GPU. CUDA vs CPU parity on the same FP16 file is G4, measured on Colab.

## Models

| File | SHA-256 | Size | Origin |
|---|---|---:|---|
| `model_int8.onnx` (the v6 release) | `be5fba5b2c94…` | 118.5 MB | dynamic INT8 quantization of the FP32 export (`train/export.py`) |
| `model_fp16.onnx` | `fd7a676767cf8cfc98154cb87f60b1168b74a8a0e726c723c658974a0db06162` | 235.6 MB | `train/export.py --fp16 --fp32 <run>/model_fp32.onnx` |

- Both files come from the same FP32 export of the v6 checkpoint (`work/A`).
- In the FP16 file, the inputs and the `logits` output stay FP32.
- FP16 vs FP32 on 1,024 validation windows: max |Δp| 0.0045, mean 1.6e-5. Torch vs the FP16 file: max 0.0034.
- Tokenizer, `config.json` and `thresholds.json` are those of the release.
- The model files are not in the repository. Publishing them needs the owner.

## How agreement was measured

Each set was scored twice, with the same code (`cmd/eval -scores`, `cmd/benchlong -units`). The only difference between the two runs is the model file.

A row agrees when both models are on the same side of the gateway's block threshold, 0.85. The comparison was done with `bench/gpu/compare_scores.py`.

| Set | Rows | Path |
|---|---:|---|
| `eval/data` (en, vi) | 2,176 | direct, `cmd/eval -detector fusion-ml` |
| `val_v3` (`train/data/val_v3.jsonl`) | 508 | direct, `cmd/eval` |
| bench/long dev (profile `quick`, docs.jsonl `78236eb5…`, split `dev`) | 189 documents: 5,341 L2 windows, 2,456 fused chunks | long inputs, `cmd/benchlong -split dev` |

Layer sets:
- `l2`: the classifier alone, calibrated.
- `l1,l2,l3`: the gateway's default fused score (`l1,l2` on bench/long, as in `docs/benchmark.md`).

## Result with the INT8 calibration shared

| Set | Layers | Agreement | Differ | INT8 ≥ 0.85 | FP16 ≥ 0.85 |
|---|---|---:|---:|---:|---:|
| eval/data | l2 | 98.81% | 26 | 1,055 | 1,071 |
| eval/data | l1,l2,l3 | 99.45% | 12 | 1,096 | 1,106 |
| val_v3 | l2 | 99.21% | 4 | 40 | 42 |
| val_v3 | l1,l2,l3 | 99.21% | 4 | 35 | 37 |
| bench/long dev | l2 (windows) | 99.89% | 6 | 199 | 197 |
| bench/long dev | l1,l2 (chunks) | 99.76% | 6 | 186 | 192 |

Agreement is below 99.5% on eval/data and val_v3, so the FP16 model gets its own calibration, as the spec asks.

Mean |Δscore| is 0.002–0.010. The rows that flip are near the threshold, plus a few attacks that FP16 scores much higher, for example:
- a Vietnamese attack: 0.40 → 0.98;
- a `split_far` chunk: 0.17 → 0.98.

FP16 is the closer copy of the FP32 model. Most of the difference is INT8 quantization noise.

## FP16 calibration

- **Method.** `cmd/calibrate fit` scored the FP16 file on the same 12,785 validation rows that calibrated v6:
  - the v4-A build's `val*`;
  - `v6_val` and `val_v6`;
  - the owner-supplied and OTP/KYC rows. These stayed on the laptop.
- **Check of the procedure.** Refitting the INT8 model the same way gives the shipped values exactly: Platt A 0.8582, B −0.2526.
- **FP16 fit.** Out of fold, L2 alone:

  | | INT8 | FP16 |
  |---|---:|---:|
  | AUC | 0.9979 | 0.9976 |
  | TPR at FPR ≤ 1% | 0.9808 | 0.9825 |

  The fitted values are below. `l2_untrusted_max` is 0.88, unchanged.

  | | INT8 (shipped) | FP16 block |
  |---|---|---|
  | Platt A, B | 0.8582, −0.2526 | 0.8634, −0.4518 |
  | logreg l1,l2 W, B | 0.4963 0.9434 0, 0.4418 | 0.4969 0.9414 0, 0.4278 |
  | logreg l1,l2,l3 W, B | 0.4714 0.9148 0.3855, 0.6131 | 0.4705 0.9127 0.3594, 0.5755 |

- **Where the block goes.** It is the `fp16` block of `calibration.json` (`internal/inference/ml`). It applies only when the classifier is loaded from `model_fp16.onnx`. `cmd/calibrate fit -write -fp16` writes it.
- **Not published yet.** The v6 `calibration.json` with this block is ready outside the repository (SHA-256 `ab7281b6…`). It ships with `model_fp16.onnx` at the release.

Agreement with the FP16 calibration (the top-level block is unchanged):

| Set | Layers | Agreement | Differ | INT8 ≥ 0.85 | FP16 ≥ 0.85 |
|---|---|---:|---:|---:|---:|
| eval/data | l2 | 99.03% | 21 | 1,055 | 1,064 |
| eval/data | l1,l2,l3 | 99.40% | 13 | 1,096 | 1,103 |
| val_v3 | l2 | 99.21% | 4 | 40 | 40 |
| val_v3 | l1,l2,l3 | 99.61% | 2 | 35 | 35 |
| bench/long dev | l2 | 99.87% | 7 | 199 | 196 |
| bench/long dev | l1,l2 | 99.76% | 6 | 186 | 192 |

The recalibration moves the threshold crossings back to INT8's counts on val_v3, but agreement stays near 99%. The rows that differ are differences between the models themselves, not a calibration offset.

## Accuracy

eval/data is used for reporting only. Nothing was fitted on it.

| Layers | Model | AUC | TPR at FPR ≤ 1% | TPR / FPR at 0.85 | Gateway rule TPR / FPR |
|---|---|---:|---:|---:|---:|
| l2 | INT8 | 0.9856 | 0.9283 | 0.894 / 0.008 | 0.905 / 0.008 |
| l2 | FP16, shared calibration | 0.9866 | 0.9325 | 0.907 / 0.009 | 0.918 / 0.009 |
| l2 | FP16, own calibration | 0.9866 | 0.9325 | 0.901 / 0.009 | 0.912 / 0.009 |
| l1,l2,l3 | INT8 | 0.9865 | 0.9479 | 0.931 / 0.006 | 0.942 / 0.006 |
| l1,l2,l3 | FP16, shared calibration | 0.9876 | 0.9522 | 0.939 / 0.007 | 0.950 / 0.007 |
| l1,l2,l3 | FP16, own calibration | 0.9876 | 0.9530 | 0.936 / 0.007 | 0.947 / 0.007 |

On val_v3 (l1,l2,l3):
- TPR is 1.0 for all three.
- FPR at 0.85 is 0.0084 for INT8, 0.0126 for FP16 with the shared calibration, and 0.0084 for FP16 with its own calibration.

## Decision
- The FP16 model's TPR at FPR ≤ 1% is not lower than INT8's: it is 0.4–0.5 points higher on eval/data.
- The GPU option therefore ships `model_fp16.onnx` with its own `fp16` calibration block.
- Expect about 1% of decisions near the threshold to differ from the CPU's INT8 model. The GPU is a different, slightly more accurate copy of the same model, not a bit-identical one.
- The CPU default keeps INT8 and its calibration unchanged.
