#!/usr/bin/env bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# v7 (RF-895d3533 R6, reports/v7_preregistration.md): the laptop side. Training runs on a Colab L4 with the
# colab-gpu skill (one job per arm, `stage` prepares what each job uploads); everything that decides runs
# here, on ONNX INT8 on the CPU, one heavy job at a time.
#
#   GUARD_V7_WORK=... ./run_arms_v7.sh stage <arm>          # $WORK/stage/<arm>: only the files train.py reads
#   GUARD_V7_WORK=... ./run_arms_v7.sh export <arm>         # INT8 export + cmd/calibrate fit -write
#   GUARD_V7_WORK=... ./run_arms_v7.sh refs                 # v3b and L1 alone (gate references, current code)
#   GUARD_V7_WORK=... ./run_arms_v7.sh gates <name> [dir]   # G1-G7 reports + the long5 long-path dumps
#   GUARD_V7_WORK=... ./run_arms_v7.sh select               # longdoc_v7.py dev + select_v7.py
#   GUARD_V7_WORK=... ./run_arms_v7.sh holdout <name> [dir] # long6 (once), after the decision
#
# Arms (identical settings, seed 20261105, 5 epochs, validation = the v6 validation files):
#   ref = v6 arm A retrained on the L4 (v4-A training data + v6_train)
#   B   = ref + v7_train (benign long-text windows: v7_long, v7_hardneg, v7_gen)
#   C   = B with the mined hard negatives (kind v7_hardneg) three times per epoch
#
# Environment: GUARD_V7_WORK (default ~/WorkingSpace/AI_R_D/guardspec-data/v7/work), GUARD_DATA_V4A,
# GUARD_V6_OUT, GUARD_V7_OUT (data/build_v7.py output), BENCH_CACHE (bench/long corpora), GUARD_R5 (the R5
# directory: long5-dev, long5-holdout, embedded-dev, embedded-holdout), GUARD_LONG6 (long6 benign and
# attack corpora). Owner rows never enter git; `stage` copies only train.jsonl and the validation files
# train.py reads (never a hold-out file).
set -euo pipefail

TRAIN=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$TRAIN/.." && pwd)
D=${GUARD_DATA:-$HOME/WorkingSpace/AI_R_D/guardspec-data}
WORK=${GUARD_V7_WORK:-$D/v7/work}
V4A=${GUARD_DATA_V4A:-$D/v6/work/data-v4A}
V6OUT=${GUARD_V6_OUT:-$D/v6/out-full}
V7OUT=${GUARD_V7_OUT:-$D/v7/data}
BENCH=${BENCH_CACHE:-$D/v6/bench-cache}/long
R5=${GUARD_R5:-$D/v6/r5}
LONG6=${GUARD_LONG6:-$D/v7/long6}
V3B=$REPO/models/local/guardspec-classifier-v3b
UV="uv run --frozen"
mkdir -p "$WORK/logs"
LOG=$WORK/logs
say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG/run.log"; }
export CGO_LDFLAGS="-L$REPO/.onnx/lib" ONNXRUNTIME_LIB="${ONNXRUNTIME_LIB:-$REPO/.onnx/lib/libonnxruntime.dylib}"

val_files() {
  local v
  v=$(printf '%s,' "$V4A"/{val,val_hard,val_vi_variants,val_v3,val_v4}.jsonl "$V6OUT"/{v6_val,val_v6}.jsonl)
  echo "${v%,}"
}

bins() { # one build of each tool per commit
  local c; c=$(git -C "$REPO" rev-parse --short HEAD)
  BIN=$WORK/bin/$c
  if [ ! -x "$BIN/benchlong" ]; then
    mkdir -p "$BIN"
    (cd "$REPO" && go build -tags onnx -o "$BIN/benchlong" ./cmd/benchlong && go build -tags onnx -o "$BIN/eval" ./cmd/eval)
  fi
}

stage_stage() {
  local arm=${1:?stage <arm>} s=$WORK/stage/$1
  rm -rf "$s" && mkdir -p "$s/data-v4A" "$s/out-full"
  for f in train val val_hard val_vi_variants val_v3 val_v4; do cp "$V4A/$f.jsonl" "$s/data-v4A/"; done
  for f in v6_train v6_val val_v6; do cp "$V6OUT/$f.jsonl" "$s/out-full/"; done
  if [ "$arm" != ref ]; then mkdir -p "$s/v7" && cp "$V7OUT/v7_train.jsonl" "$s/v7/"; fi
  (cd "$s" && find . -type f -name '*.jsonl' | sort | xargs shasum -a 256) | tee "$s.sha256"
}

stage_export() {
  local arm=${1:?export <arm>} run=$WORK/runs/$1
  [ -d "$run/best" ] || { echo "no $run/best (fetch the Colab run first)" >&2; exit 1; }
  if [ ! -f "$run/model/calibration.json" ]; then
    say "export: $arm"
    $UV python export.py --run-dir "$run" --out-dir "$run/model" --data-dir "$V4A" --v6-dir "$V6OUT" 2>&1 | tee -a "$LOG/export_$arm.log"
    (cd "$REPO" && go run -tags onnx ./cmd/calibrate fit -write -l2 "$run/model" -val "$(val_files)") 2>&1 | tee -a "$LOG/calibrate_$arm.log"
  fi
}

run_eval() { # <out.json> <l2 dir or ""> <data dir> <path> [flags]
  local out=$1 l2=$2 data=$3 path=$4; shift 4
  [ -f "$out" ] && return 0
  mkdir -p "$(dirname "$out")"
  say "eval: $out"
  if [ -z "$l2" ]; then
    (cd "$REPO" && "$BIN/eval" -data "$data" -path "$path" -json "$out.tmp" "$@") >>"$LOG/eval.log" 2>&1
  else
    (cd "$REPO" && L2_MODEL_DIR=$l2 "$BIN/eval" -detector fusion-ml -data "$data" -path "$path" -json "$out.tmp" "$@") >>"$LOG/eval.log" 2>&1
  fi
  mv "$out.tmp" "$out"
}

g5_data() {
  if [ ! -f "$WORK/g5/val_v3/val_v3.jsonl" ]; then
    $UV python holdout_evalset.py --data-dir "$V4A" --split-file "val_v3=$V4A/val_v3.jsonl" --splits val_v3 \
      --out "$WORK/g5/val_v3" >>"$LOG/eval.log" 2>&1
  fi
  echo "$WORK/g5/val_v3"
}

short_gates() { # <gates dir> <l2 dir>
  local g=$1 l2=$2 g5; g5=$(g5_data)
  run_eval "$g/eval.json" "$l2" eval/data direct
  run_eval "$g/codelog.json" "$l2" eval/codelog tool -corroboration off
  run_eval "$g/embedded.json" "$l2" eval/embedded tool -corroboration off
  run_eval "$g/val_v3.json" "$l2" "$g5" direct
}

longpath() { # <corpus dir> <dump prefix> <l2 dir> <label>
  local corpus=$1 dump=$2 l2=$3 label=$4
  [ -f "$dump.json" ] && return 0
  mkdir -p "$(dirname "$dump")"
  say "long path: $dump"
  (cd "$REPO" && L2_MODEL_DIR=$l2 "$BIN/benchlong" -corpus "$corpus" -profile "$label" -layers none -l2pass off -long on \
    -dump "$dump" -skip-latency -workers "${BENCH_WORKERS:-4}" -host "m3max-$label" -out "$dump.tmp.json") >"$dump.log" 2>&1
  mv "$dump.tmp.json" "$dump.json"; mv "$dump.tmp.md" "$dump.md"
}

long5_corpora() { # long5 is v7 dev: both halves in one corpus, the R5 attack documents of both halves in another
  local c=$WORK/corpora
  if [ ! -f "$c/long5/docs.jsonl" ]; then
    mkdir -p "$c/long5" "$c/long5-attack"
    cat "$R5/long5-dev/docs.jsonl" "$R5/long5-holdout/docs.jsonl" > "$c/long5/docs.jsonl"
    cat "$R5/embedded-dev/docs.jsonl" "$R5/embedded-holdout/docs.jsonl" > "$c/long5-attack/docs.jsonl"
  fi
}

stage_refs() {
  bins
  short_gates "$WORK/gates/v3b" "$V3B"
  run_eval "$WORK/gates/l1/embedded.json" "" eval/embedded tool
}

stage_gates() {
  local name=${1:?gates <name> [model dir]} l2=${2:-$WORK/runs/$1/model}
  bins
  long5_corpora
  short_gates "$WORK/gates/$name" "$l2"
  local out=$WORK/gates/$name/benchlong-full.json
  if [ ! -f "$out" ]; then
    say "bench: $out"
    (cd "$REPO" && L2_MODEL_DIR=$l2 "$BIN/benchlong" -corpus "$BENCH/full" -profile full -layers "l1;l1,l2" -skip-latency \
      -workers "${BENCH_WORKERS:-4}" -l2cap on -out "$out.tmp.json") >>"$LOG/bench.log" 2>&1
    mv "$out.tmp.json" "$out"; mv "$out.tmp.md" "${out%.json}.md"
  fi
  longpath "$WORK/corpora/long5" "$WORK/dumps/$name/benign" "$l2" "long5-$name"
  longpath "$WORK/corpora/long5-attack" "$WORK/dumps/$name/attack" "$l2" "long5-attack-$name"
}

stage_select() {
  local args=() n
  for n in ${ARMS:-B C} ref; do
    args+=(--model "$n=$WORK/runs/$n/model" --benign "$n=$WORK/dumps/$n/benign" --attack "$n=$WORK/dumps/$n/attack")
  done
  # the released v6 (MPS) for the record: its R5 dumps with the r5 rules are the same pipeline on the same documents
  mkdir -p "$WORK/dumps/v6rel"
  for k in benign attack; do
    local src=$([ $k = benign ] && echo benign || echo attack)
    ln -sf "$R5/dumps/$src-r5-dev.jsonl.gz" "$WORK/dumps/v6rel/$k-dev.jsonl.gz"
    ln -sf "$R5/dumps-holdout/$src-r5-holdout.jsonl.gz" "$WORK/dumps/v6rel/$k-holdout.jsonl.gz"
  done
  args+=(--model "v6rel=$D/v6/release/guardspec-classifier-v6" --benign "v6rel=$WORK/dumps/v6rel/benign" --attack "v6rel=$WORK/dumps/v6rel/attack")
  $UV python longdoc_v7.py --stage dev --out "$WORK/select" "${args[@]}"
  local arms; arms=$(echo "${ARMS:-B C}" | tr ' ' ',')
  $UV python select_v7.py --arms "$arms" --ref ref --gates "$WORK/gates" --longdoc "$WORK/select/v7_dev_longdoc.json" \
    --runs "$WORK/runs" --out "$TRAIN/reports/v7_dev.json"
}

stage_holdout() {
  local name=${1:?holdout <name> [model dir]} l2=${2:-$WORK/runs/$1/model}
  bins
  longpath "$LONG6/corpus" "$WORK/holdout/$name/benign" "$l2" "long6-$name"
  longpath "$LONG6/attack" "$WORK/holdout/$name/attack" "$l2" "long6-attack-$name"
}

case ${1:-} in
  stage) stage_stage "${2:-}" ;;
  export) stage_export "${2:-}" ;;
  refs) stage_refs ;;
  gates) stage_gates "${2:-}" "${3:-}" ;;
  select) stage_select ;;
  holdout) stage_holdout "${2:-}" "${3:-}" ;;
  *) echo "usage: $0 stage|export|gates|holdout <arm> | refs | select" >&2; exit 2 ;;
esac
