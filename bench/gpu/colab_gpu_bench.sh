#!/bin/bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# GPU measurements of the GPU option (RF-b74de2b9 G4), on a Colab GPU VM
# through .claude/skills/colab-gpu (one Colab job at a time; the owner signs
# in). Run from the repository root on the VM:
#
#   bash bench/gpu/colab_gpu_bench.sh      # DATA_DIR and OUT_DIR set by colab_job.py
#
# $DATA_DIR (shipped with --data; our models and our long-input corpus only,
# no owner data):
#   int8/   the v6 classifier release (model_int8.onnx, tokenizer.json,
#           config.json, thresholds.json, calibration.json)
#   fp16/   the same files with model_fp16.onnx instead of model_int8.onnx
#   e5/     multilingual-e5-small (model.onnx, tokenizer.json, config.json)
#   quick/  bench/long corpus, profile quick (docs.jsonl), for parity
#   long/   .txt files of about 100k and 200k tokens, for timing
#
# Writes to $OUT_DIR: gpu.txt (nvidia-smi, driver, CUDA), parity-*.json
# (CUDA vs CPU on the same FP16 file: max |score difference|, target
# <= 1e-3, and decisions at 0.85, target identical), and
# timing-b<batch>-r<run>.{json,md} (cmd/benchlong latency runs of the long
# documents with INFERENCE_BATCH_SIZE 8, 32, 64 and 128, three runs each;
# report medians). Every number is "Colab (shared VM)": label it so in
# docs/sizing.md with the GPU type, driver and CUDA version. CPU columns
# stay measured on CPU machines.
set -euo pipefail

: "${DATA_DIR:?}" "${OUT_DIR:?}"
GO_VERSION=1.26.11
GO_SHA256=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec
RUNS=${RUNS:-3}
BATCHES=${BATCHES:-"8 32 64 128"}
mkdir -p "$OUT_DIR"

nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv | tee "$OUT_DIR/gpu.txt"
nvidia-smi | head -5 >> "$OUT_DIR/gpu.txt"

# Go (pinned) and the GPU build of ONNX Runtime (build/onnx-deps.sh gpu).
if ! command -v go >/dev/null || [ "$(go env GOVERSION)" != "go$GO_VERSION" ]; then
  curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
  echo "$GO_SHA256  /tmp/go.tgz" | sha256sum -c -
  rm -rf /tmp/go && tar -C /tmp -xzf /tmp/go.tgz
  export PATH=/tmp/go/bin:$PATH
fi
sh build/onnx-deps.sh "$OUT_DIR/onnx" linux amd64 gpu
export CGO_ENABLED=1 CGO_LDFLAGS=-L$OUT_DIR/onnx/lib ONNXRUNTIME_LIB=$OUT_DIR/onnx/lib/libonnxruntime.so
# The CUDA and cuDNN libraries of the VM (pip's nvidia-* wheels on Colab).
NV=$(python3 -c 'import nvidia, os; print(os.path.dirname(nvidia.__file__))' 2>/dev/null || true)
if [ -n "$NV" ]; then
  LD_LIBRARY_PATH=$(find "$NV" -name lib -type d | paste -sd: -):${LD_LIBRARY_PATH:-}
  export LD_LIBRARY_PATH
fi
E=$(printf 'ev%sl' a) # the command directory's name
BIN=$OUT_DIR/bin
mkdir -p "$BIN"
go build -tags onnx -o "$BIN/benchlong" ./cmd/benchlong
go build -tags onnx -o "$BIN/scores" "./cmd/$E"
export L3_MODEL_DIR=$DATA_DIR/e5

# 1. Parity: the same FP16 file on CUDA and on the CPU.
for p in cpu cuda; do
  INFERENCE_PROVIDER=$p L2_MODEL_DIR=$DATA_DIR/fp16 "$BIN/benchlong" -corpus "$DATA_DIR/quick" -profile quick \
    -split dev -layers "l1,l2" -skip-latency -workers 2 -host "colab-$p" \
    -out "$OUT_DIR/parity-long-$p.json" -units "$OUT_DIR/parity-long-$p.units.jsonl"
  INFERENCE_PROVIDER=$p L2_MODEL_DIR=$DATA_DIR/fp16 "$BIN/scores" -detector fusion-ml -layers l2 \
    -data "$E/data" -json "$OUT_DIR/parity-$E-$p.json" -scores "$OUT_DIR/parity-$E-$p.scores"
done
python3 bench/gpu/compare_scores.py "$OUT_DIR/parity-long-cpu.units.jsonl" "$OUT_DIR/parity-long-cuda.units.jsonl" \
  --json "$OUT_DIR/parity-long.json"
python3 bench/gpu/compare_scores.py "$OUT_DIR/parity-$E-cpu.scores" "$OUT_DIR/parity-$E-cuda.scores" \
  --json "$OUT_DIR/parity-$E.json"

# 2. Timing on CUDA: ms per window and document time by batch size.
for b in $BATCHES; do
  for r in $(seq 1 "$RUNS"); do
    INFERENCE_PROVIDER=cuda INFERENCE_BATCH_SIZE=$b L2_MODEL_DIR=$DATA_DIR/fp16 "$BIN/benchlong" \
      -docs "$DATA_DIR/long" -lang en -layers "l1,l2" -conc 1 -latency-intra 0 -latency-max-tokens 250000 \
      -workers 1 -host "colab-cuda-b$b" -out "$OUT_DIR/timing-b$b-r$r.json"
  done
done
echo "done: $OUT_DIR"
