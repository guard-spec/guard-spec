#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Stages the guardspec-classifier (v3b) Hugging Face repository in a local
# directory: the four model files, calibration.json and the model card. It
# uploads nothing; publish the directory yourself, for example:
#
#   train/hf/stage.sh /tmp/guardspec-classifier
#   huggingface-cli upload <org>/guardspec-classifier /tmp/guardspec-classifier .
#
# Usage: train/hf/stage.sh <staging-dir> [model-dir]
#   model-dir defaults to models/local/guardspec-classifier-v3b of this checkout.
#
# The SHA-256 of every model file is checked against
# build/gateway-full.l2.sha256 (the pin the gateway-full image builds with), so
# a different export cannot be staged by mistake.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dest=${1:?usage: train/hf/stage.sh <staging-dir> [model-dir]}
src=${2:-$root/models/local/guardspec-classifier-v3b}
pins=$root/build/gateway-full.l2.sha256

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$@"; }
else
  sha() { shasum -a 256 "$@"; }
fi

mkdir -p "$dest"
for f in model_int8.onnx tokenizer.json config.json thresholds.json; do
  [ -f "$src/$f" ] || { echo "stage.sh: missing $src/$f" >&2; exit 1; }
  cp "$src/$f" "$dest/$f"
done
cp "$here/calibration.json" "$dest/calibration.json"
cp "$here/README.md" "$dest/README.md"

(cd "$dest" && sha -c "$pins") >&2 || {
  echo "stage.sh: staged files do not match $pins" >&2
  exit 1
}

echo "Staged in $dest (nothing uploaded). SHA-256:"
(cd "$dest" && sha model_int8.onnx tokenizer.json config.json thresholds.json calibration.json README.md)
