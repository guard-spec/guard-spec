#!/bin/bash
# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# R8c measures for one model (train/reports/r8c_preregistration.md, "Measures"); ONNX INT8, laptop CPU, the
# gateway path, binaries built once from this checkout (the commit is recorded). Each holdout is scored once per model: a lock file
# per (model, holdout) refuses a second run.
#
#   train/measure_r8c.sh <name> <L2 model dir>
#
#   eval/data        cmd/eval -detector fusion-ml (l1,l2,l3); the verdict reads the hold-out half
#   persona3         cmd/eval -detector fusion-ml -path direct -data <persona3 holdout>
#   split1           cmd/eval -layers l2 (L2 only) on the conversation windows (turns joined with a space), and
#                    on the single turns (supplementary)
#   long9            cmd/benchlong -layers none -l2pass off -long on (the long path, shipped long_doc, the model's
#                    calibration), benign and attack documents, window dumps
#
# Environment: R8C (default ~/WorkingSpace/AI_R_D/guardspec-data/v9/r8c), ONNX_LIB (directory of
# libonnxruntime.dylib and libtokenizers.a), MODEL_ROOT (the MODEL_DIR whose cache/ holds multilingual-e5-small, the L3 embedder),
# ONLY (space-separated subset of: data persona3 split long), and for later rounds HOLDOUTS (the round's holdout
# directory with its SHA256SUMS, default $R/out), P3_DIR (the persona3 holdout, default
# $HOLDOUTS/persona3/holdout/direct), LONG (long9) and SPLIT (split1): R8d runs with R8C=.../v9/r8d LONG=long10
# SPLIT=split2 P3_DIR=.../v9/r8c/out/persona3/holdout/direct. EVALSETS (R8e) lists further cmd/eval holdouts as
# name=directory pairs, scored with -path direct and selected with ONLY token "evalsets": R8e runs with
# R8C=.../v9/r8e LONG=long11 EVALSETS="vi1=$H/vi1/holdout tp1=$H/tp1/holdout" ONLY="evalsets long".
set -euo pipefail
n=$1; m=$2
R=${R8C:-$HOME/WorkingSpace/AI_R_D/guardspec-data/v9/r8c}
H=${HOLDOUTS:-$R/out}
LONG=${LONG:-long9}; SPLIT=${SPLIT:-split1}
P3=${P3_DIR:-$H/persona3/holdout/direct}
O=$R/measure/$n; mkdir -p "$O"
W=$(cd "$(dirname "$0")/.." && pwd)
: "${ONNX_LIB:?set ONNX_LIB}" "${MODEL_ROOT:?set MODEL_ROOT}"
export CGO_LDFLAGS="-L$ONNX_LIB" ONNXRUNTIME_LIB="$ONNX_LIB/libonnxruntime.dylib" MODEL_DIR="$MODEL_ROOT"
B=$R/measure/bin; mkdir -p "$B"
cd "$W"
# One build serves every model of the round (the commit is recorded; delete $B to rebuild).
if [ ! -x "$B/eval" ] || [ ! -x "$B/benchlong" ]; then
  [ -z "$(git status --porcelain -- cmd internal go.mod go.sum)" ] || { echo "uncommitted Go changes" >&2; exit 1; }
  go build -tags onnx -o "$B/eval" ./cmd/eval
  go build -tags onnx -o "$B/benchlong" ./cmd/benchlong
  git rev-parse HEAD > "$B/commit.txt"
  shasum -a 256 "$B/eval" "$B/benchlong" > "$B/SHA256SUMS"
fi
cp "$B/commit.txt" "$O/commit.txt"
{ echo "dir $m"; shasum -a 256 "$m/model_int8.onnx" "$m/calibration.json"; echo "model_root $MODEL_ROOT"; \
  shasum -a 256 "$MODEL_ROOT/cache/multilingual-e5-small/model.onnx"; } > "$O/model.txt"

# the holdout files must be the pre-registered ones
(cd "$H" && shasum -a 256 -c SHA256SUMS)
[ -z "${P3_DIR:-}" ] || (cd "$P3/../../.." && grep "  persona3/" SHA256SUMS | shasum -a 256 -c -)

once() {  # once <holdout>: refuse to score a holdout twice with one model
  if [ -e "$O/$1.lock" ]; then echo "$n: $1 already scored" >&2; return 1; fi
  date -u +%FT%TZ > "$O/$1.lock"
}
want() { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }
t() { echo "$(date +%T) $n $*"; }

if want data && once data; then
  s=$SECONDS
  L2_MODEL_DIR=$m "$B/eval" -detector fusion-ml -json "$O/data.json" -scores "$O/data.scores.jsonl" > "$O/data.log" 2>&1
  t "eval/data done in $((SECONDS - s)) s"
fi
if want persona3 && once persona3; then
  s=$SECONDS
  L2_MODEL_DIR=$m "$B/eval" -detector fusion-ml -path direct -data "$P3" \
    -json "$O/persona3.json" -scores "$O/persona3.scores.jsonl" > "$O/persona3.log" 2>&1
  t "persona3 done in $((SECONDS - s)) s"
fi
if want split && once "$SPLIT"; then
  s=$SECONDS
  python3 train/verdict_r8c.py prep-split1 --split1 "$H/$SPLIT/$SPLIT.json" --out "$R/measure/$SPLIT-eval" > /dev/null
  L2_MODEL_DIR=$m "$B/eval" -layers l2 -path direct -data "$R/measure/$SPLIT-eval/window" \
    -json "$O/$SPLIT.json" -scores "$O/$SPLIT.scores.jsonl" > "$O/$SPLIT.log" 2>&1
  L2_MODEL_DIR=$m "$B/eval" -layers l2 -path direct -data "$R/measure/$SPLIT-eval/turns" \
    -json "$O/${SPLIT}_turns.json" -scores "$O/${SPLIT}_turns.scores.jsonl" > "$O/${SPLIT}_turns.log" 2>&1
  t "$SPLIT done in $((SECONDS - s)) s"
fi
for es in ${EVALSETS:-}; do
  name=${es%%=*}; dir=${es#*=}
  if want evalsets && once "$name"; then
    s=$SECONDS
    L2_MODEL_DIR=$m "$B/eval" -detector fusion-ml -path direct -data "$dir" \
      -json "$O/$name.json" -scores "$O/$name.scores.jsonl" > "$O/$name.log" 2>&1
    t "$name done in $((SECONDS - s)) s"
  fi
done
if want long && once "$LONG"; then
  for k in benign attack; do
    s=$SECONDS
    L2_MODEL_DIR=$m "$B/benchlong" -corpus "$H/$LONG/$k" -profile "$(basename "$R")-$n-$k" -layers none -l2pass off -long on \
      -dump "$O/$LONG-$k" -skip-latency -workers 4 -host m3max-$(basename "$R") -out "$O/$LONG-$k.json" > "$O/$LONG-$k.log" 2>&1
    t "$LONG $k done in $((SECONDS - s)) s"
  done
fi
python3 train/verdict_r8c.py summarize --dir "$O" > /dev/null
t "summary written"
