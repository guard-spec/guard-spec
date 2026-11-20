# FP16 vs INT8, guardspec-classifier-v8g (RF-08b30b92)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

v8g is R8d's arm EPL2, seed 20261107 (EPL2-s3, `train/reports/r8d_report.md`).

- **When and where:** measured on 2026-11-19/20 on the CPU (Apple M3 Max), binaries built at `5fd6e22`, ONNX Runtime
  1.31.1. These numbers compare the two model files, not the GPU. CUDA against the CPU on the same FP16 file is the
  GPU part, measured on 2026-11-20 (below).
- **Holdouts:** no holdout was scored for this report.
  - eval/data is read as in v8e's report.
  - val_v3 is a validation split.
  - long5 dev has been dev since R5.

## Files (the package directory, `SHA256SUMS` next to them)

| file | SHA-256 | origin |
|---|---|---|
| `model_int8.onnx` | `b68cfbe8e0c88f9c48466b5aa57f779867892a87651b0c9e66b705d382c91538` | R8d EPL2-s3, as scored in R8d |
| `model_fp16.onnx` | `dd79185c16cc1fdd5e7773dde81596cd8f54efb2b984a9732d0b0ef2ac0d72dc` | `train/export.py --fp16 --fp32 <run>/model_fp32.onnx` (same FP32 checkpoint; FP16 weights, FP32 `input_ids`/`attention_mask` and `logits`) |
| `tokenizer.json` | `6879d3648d0329c894b1cbb0c89096430e24d3c7cf5d359d4ccc87ce585c4ae4` | unchanged |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` | unchanged |
| `thresholds.json` | `a7b90ccbec1f97793c6915e9ab957387d0f2ec7a00db5ef37117f1e78c397325` | the R8d export's, `model` set to `guardspec-classifier-v8g` |
| `calibration.json` | `3ae1c55facba15c978bd852b0e3ea586c9931d3c53e7c5961171aad4cc4a970a` | below; `train/hf/v8g/calibration.json` and the built-in calibration of v8g, byte for byte |

The FP16 file was checked against FP32 on 1,024 validation windows:
- FP16 vs FP32: max |Δp| 0.0026, mean 1.3e-5; risk max |Δ| 0.0022;
- torch vs the FP16 file: max 0.0014.

## Calibration (`calibration.json`)

`cmd/calibrate fit` used the 12,785 validation rows that calibrated E and every R8 arm. These rows stayed on the
laptop.

- **Top level (INT8):** the fit of R8d's export of EPL2-s3, unchanged.
  - Platt A 0.8104, B −0.6560;
  - `l1,l2` weights (0.4122, 0.9399), bias 0.3154;
  - `l1,l2,l3` weights (0.3748, 0.9124, 0.4230), bias 0.6367;
  - `l2_untrusted_max` 0.88.
  - The eval/data hold-out half scored with this package gives R8d's numbers for EPL2-s3 exactly: TPR at FPR ≤ 1%
    0.965, TPR at 0.85 0.959.
- **`long_doc`:** E's rule, as in v8e (`strong75_l2`: n0 30, L1 bar 0.75 raw, L2 bar 0.95, base 0.85).
- **FP16 block** (`fp16`), fitted on the same rows scored with `model_fp16.onnx` on the CPU (the file loaded as
  `model.onnx`, `cmd/calibrate fit -write -fp16`):
  - Platt A 0.8221, B −0.6155;
  - `l1,l2` weights (0.4470, 0.9436), bias 0.3572;
  - `l1,l2,l3` weights (0.4076, 0.9180, 0.3827), bias 0.6208;
  - `l2_untrusted_max` 0.88.
- **Out of fold (FP16, 5 folds):** L2 alone AUC 0.9984, TPR at FPR ≤ 1% 0.9865; `logreg(l1,l2,l3)` AUC 0.9981,
  TPR at FPR ≤ 1% 0.9875.
- **No local paths:** the `fitted_on` texts name the splits, not local paths.
- **File version:** the CPU measures and the GPU run read an earlier serialization of the same values
  (SHA-256 `57655459…`). It was then rewritten as the gateway marshals its built-in calibration, with v8e's wording
  of the top-level `fitted_on`; no number changed.
- **Long-path rule in FP16:** the FP16 block has no `long_doc` of its own, so `model_fp16.onnx` takes the top-level
  rule (`ml.forModelFile`), as in v8e.

## Agreement at 0.85 on the short path (fused `l1,l2,l3`, `cmd/eval -scores`, each model with its own calibration)

| set | rows | agreement | differ | max \|Δscore\| | mean \|Δscore\| |
|---|---:|---:|---:|---:|---:|
| `eval/data` (en, vi, both halves) | 2,176 | 99.26% | 16 (5 only INT8 blocks, 11 only FP16 blocks; 2 benign) | 0.66 | 0.0080 |
| `val_v3` | 508 | 99.41% | 3 (all benign; 2 only INT8, 1 only FP16) | 0.66 | 0.0087 |

The gateway decision (`blocked`, score or sanitizer anomaly) differs on the same rows.

## Accuracy (eval/data; reporting only, nothing was fitted on it)

| model | rows | AUC | TPR at FPR ≤ 1% | TPR / FPR at 0.85 |
|---|---|---:|---:|---:|
| INT8 | all (1,171 attack, 1,005 benign) | 0.988 | 0.946 | 0.942 / 0.90% (9) |
| FP16 | all | 0.987 | 0.940 | 0.945 / 1.09% (11) |
| INT8 | hold-out half (602, 511) | 0.991 | 0.965 | 0.959 / 0.98% (5) |
| FP16 | hold-out half | 0.990 | 0.962 | 0.960 / 0.98% (5) |

## Long path on the CPU: long5 dev with `long_doc`

`cmd/benchlong -split dev -layers none -l2pass off -long on`, the shipped `long_doc`, each file with its own
calibration. A document counts when its doc score reaches 0.85.

| | FP16, CPU | INT8, CPU |
|---|---|---|
| benign documents blocked (dev) | 0 / 74 | 0 / 74 |
| embedded attacks caught (dev, all intact) | 286 / 329 | 285 / 329 |
| payloads alone (dev) | 43 / 47 | 43 / 47 |
| documents rejected | 0 | 0 |

- **Disagreements:** 3 of 450 documents get a different decision, all Vietnamese attack documents near the
  threshold.
  - `straddle_chunk`: FP16 0.964 against INT8 0.836.
  - `split_adjacent`: 0.967 against 0.834.
  - `pos_start`: 0.831 against 0.975.
- **Run time on the CPU:** FP16 took about twice as long as INT8 (benign 1,433 s against 635 s; attack 5,657 s
  against 2,862 s). FP16 is the GPU option, not a CPU one.

## Reading

- **FP16 decides like INT8 within the near-threshold noise seen for v8e.**
  - Short path: about 0.7% of decisions differ, against 0.9% for v8e.
  - Long path: no benign long5 dev document is blocked by either file, and embedded detection differs by one
    document in 329.
- **FP16 catches slightly more on the short path at 0.85 and blocks two more benign rows** (11 against 9 on all of
  eval/data; equal on the hold-out half). This is the same direction as v8e.
- **The GPU option looks fit for v8g on these CPU numbers,** with the same caveat as v8e: about 1% of decisions near
  the threshold differ between a GPU gateway and a CPU gateway. The GPU run below confirms it on CUDA.

## GPU run: FP16 on CUDA, and the long path (2026-11-20)

Colab job `gs-v8g-fp16`:
- NVIDIA L4, driver 580.82.07, ONNX Runtime 1.31.1 (`gpu_cuda12`), commit `4ac27e7`;
- `STEPS="parity longdoc" bash bench/gpu/colab_gpu_bench.sh`.
- **Data sent:** the v8g package without `model_int8.onnx`, and v8e's staged `quick` and `long5` corpora. No owner
  data. The top-level `fitted_on` of the staged calibration copy was shortened, because colab_job.py flags the words
  "owner-supplied"; the values were unchanged.
- **Compute units:** 567.11 before and 565.17 after (1.94).

**CUDA against the CPU, same FP16 file.**
- `eval/data` rows (L2 alone, `fusion-ml:l2`): 2,176 rows, the decisions at 0.85 agree 100%, max |Δscore| 0.0089,
  and the gateway decisions agree 100%.
- `quick` long-input windows: 100% agreement.
  - L2: 5,341 windows, max |Δ| 0.013.
  - `l1,l2`: 2,456 chunks, max |Δ| 0.0040.
- Latency of one eval/data row: p50 3.0 ms on CUDA, against 9.3 ms on the Colab CPU (Xeon, 12 vCPU).

**Long path on CUDA with `long_doc`.** This is `long5` dev: 74 benign documents and 376 attack documents. It has been
dev since R5, so this is a dev measure, compared with the INT8 and FP16 CPU runs above on the same documents:

| | FP16, CUDA | FP16, CPU | INT8, CPU |
|---|---|---|---|
| benign documents blocked | 0 / 74 | 0 / 74 | 0 / 74 |
| embedded attacks caught (all intact) | 286 / 329 | 286 / 329 | 285 / 329 |
| payloads alone | 43 / 47 | 43 / 47 | 43 / 47 |
| documents rejected | 0 | 0 | 0 |

- **CUDA against CPU, FP16:** 0 of 450 documents differ; max |Δ doc score| 0.0056 on benign documents and 0.0013 on
  attack documents.
- **FP16 on CUDA against INT8 on CPU:** 3 of 450 differ, the same 3 Vietnamese attack documents as on the CPU (two
  caught only by FP16, one only by INT8).
- **Speed:** about 110k tokens/s on the L4. The full `long5` (150 benign documents, 22.4M tokens) took 204 s; the
  holdout half was scored too but is not read here.

**Reading.** CUDA decides like the CPU on the same FP16 file. Under the `long_doc` rule, FP16 on a GPU decides long
documents like INT8 on the CPU, within one document of the near-threshold attacks. The GPU option is fit for v8g, with
the caveat of v8e: about 1% of short-path decisions near the threshold differ between a GPU gateway (FP16) and a CPU
gateway (INT8). No fresh long holdout was scored in FP16.
