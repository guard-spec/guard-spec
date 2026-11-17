#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Stages the guardspec-classifier Hugging Face repository in a local
# directory: the four model files, calibration.json and the model card (and
# model_fp16.onnx, the GPU option's model, when the version's pins list it). It
# uploads nothing; publish the directory yourself, for example:
#
#   train/hf/stage.sh /tmp/guardspec-classifier
#   huggingface-cli upload <org>/guardspec-classifier /tmp/guardspec-classifier .
#
# Usage: train/hf/stage.sh <staging-dir> [model-dir] [version]
#   version defaults to v3b; model-dir defaults to
#   models/local/guardspec-classifier-<version> of this checkout.
#
# train/hf/<version>/ holds the version's calibration.json, README.md (its
# model card) and SHA256SUMS (the pins): the SHA-256 of every staged file is
# checked against them, so a different export cannot be staged by mistake.
# The Hugging Face main branch holds the recommended version
# (publish-model.yml), with that version's card.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dest=${1:?usage: train/hf/stage.sh <staging-dir> [model-dir] [version]}
version=${3:-v3b}
src=${2:-$root/models/local/guardspec-classifier-$version}
meta=$here/$version
pins=$meta/SHA256SUMS
[ -f "$pins" ] || { echo "stage.sh: no $pins for version $version" >&2; exit 1; }

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
# model_fp16.onnx (provider: cuda in models/manifest.yaml) only where the
# pins list it, so it is staged and checked like the other files.
files="model_int8.onnx tokenizer.json config.json thresholds.json"
if grep -q '[[:space:]]model_fp16\.onnx$' "$pins"; then
  [ -f "$src/model_fp16.onnx" ] || { echo "stage.sh: missing $src/model_fp16.onnx" >&2; exit 1; }
  cp "$src/model_fp16.onnx" "$dest/model_fp16.onnx"
  files="$files model_fp16.onnx"
fi
cp "$meta/calibration.json" "$dest/calibration.json"
cp "$meta/README.md" "$dest/README.md"

(cd "$dest" && sha -c "$pins") >&2 || {
  echo "stage.sh: staged files do not match $pins" >&2
  exit 1
}

echo "Staged in $dest (nothing uploaded). SHA-256:"
# shellcheck disable=SC2086 # $files is a list of plain file names
(cd "$dest" && sha $files calibration.json README.md)
