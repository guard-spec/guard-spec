#!/usr/bin/env bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# v8 (RF-3a9ce3f9 R7, reports/v8_preregistration.md): the laptop side. Training runs on a Colab L4 with the
# colab-gpu skill (one job per arm, `stage` prepares what each job uploads); everything that decides runs
# here, on ONNX INT8 on the CPU, one heavy job at a time.
#
#   GUARD_V8_WORK=... ./run_arms_v8.sh stage <D|E>           # $WORK/stage/<arm>: only the files train.py reads
#   GUARD_V8_WORK=... ./run_arms_v8.sh export <D|E>          # INT8 export + cmd/calibrate fit -write
#   GUARD_V8_WORK=... ./run_arms_v8.sh refs                  # v3b and L1 alone (gate references, current code)
#   GUARD_V8_WORK=... ./run_arms_v8.sh gates <name> [dir]    # G1-G7 reports + the long5 long-path dumps
#   GUARD_V8_WORK=... ./run_arms_v8.sh select                # longdoc_v8.py dev + select_v8.py
#   GUARD_V8_WORK=... ./run_arms_v8.sh holdout <name>        # long7 (once), after reports/v8_dev.json is committed
#   GUARD_V8_WORK=... ./run_arms_v8.sh holdout-report        # longdoc_v8.py holdout for the scored models
#
# Arms (identical settings, seed 20261105, 5 epochs, validation = the v6 validation files):
#   ref = R6's GPU reference (job v7-ref: v6 arm A retrained on the L4), reused as it is, not retrained
#   D   = ref data + v8_train.jsonl (the v7 benign windows and one attack window of the same host each, 1:1)
#   E   = ref data + v8e_train.jsonl (every v8 attack row, a seeded half of the benign rows)
# v6rel = the released v6 (MPS), scored with the same binaries, for the record.
#
# Environment: GUARD_V8_WORK (default ~/WorkingSpace/AI_R_D/guardspec-data/v8/work), GUARD_DATA_V4A,
# GUARD_V6_OUT, GUARD_V8_OUT (data/build_v8.py output), GUARD_REF_MODEL (R6's ref, exported and calibrated),
# BENCH_CACHE (bench/long corpora, long7 among them), GUARD_R5 (long5-dev, long5-holdout, embedded-dev,
# embedded-holdout), GUARD_LONG7_ATTACK (the long7 embedded-attack documents). Owner rows never enter git;
# `stage` copies only train.jsonl and the validation files train.py reads (never a hold-out file).
set -euo pipefail

TRAIN=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$TRAIN/.." && pwd)
D=${GUARD_DATA:-$HOME/WorkingSpace/AI_R_D/guardspec-data}
WORK=${GUARD_V8_WORK:-$D/v8/work}
V4A=${GUARD_DATA_V4A:-$D/v6/work/data-v4A}
V6OUT=${GUARD_V6_OUT:-$D/v6/out-full}
V8OUT=${GUARD_V8_OUT:-$D/v8/data}
REF=${GUARD_REF_MODEL:-$D/v7/work/runs/ref/model}
V6REL=${GUARD_V6_RELEASE:-$D/v6/release/guardspec-classifier-v6}
BENCH=${BENCH_CACHE:-$D/v6/bench-cache}/long
R5=${GUARD_R5:-$D/v6/r5}
LONG7_BENIGN=${GUARD_LONG7_BENIGN:-$BENCH/long7}
LONG7_ATTACK=${GUARD_LONG7_ATTACK:-$D/v8/long7/attack}
V3B=$REPO/models/local/guardspec-classifier-v3b
ARMS=${ARMS:-D E}
UV="uv run --frozen"
mkdir -p "$WORK/logs"
LOG=$WORK/logs
say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG/run.log"; }
export CGO_LDFLAGS="-L$REPO/.onnx/lib" ONNXRUNTIME_LIB="${ONNXRUNTIME_LIB:-$REPO/.onnx/lib/libonnxruntime.dylib}"

model_dir() { # <name>: ref and v6rel are fixed models, the arms are this round's runs
  case $1 in
    ref) echo "$REF" ;;
    v6rel) echo "$V6REL" ;;
    *) echo "$WORK/runs/$1/model" ;;
  esac
}

v8_file() {
  case $1 in
    D) echo v8_train.jsonl ;;
    E) echo v8e_train.jsonl ;;
    *) echo "unknown arm $1 (D or E; ref is R6's model, not retrained)" >&2; exit 2 ;;
  esac
}

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
  local arm=${1:?stage <D|E>} f; f=$(v8_file "$arm")
  local s=$WORK/stage/$arm
  rm -rf "$s" && mkdir -p "$s/data-v4A" "$s/out-full" "$s/v8"
  for x in train val val_hard val_vi_variants val_v3 val_v4; do cp "$V4A/$x.jsonl" "$s/data-v4A/"; done
  for x in v6_train v6_val val_v6; do cp "$V6OUT/$x.jsonl" "$s/out-full/"; done
  cp "$V8OUT/$f" "$s/v8/"
  if find "$s" -name '*holdout*' -o -name '*probe*' | grep -q .; then echo "hold-out file in $s" >&2; exit 1; fi
  (cd "$s" && find . -type f -name '*.jsonl' | sort | xargs shasum -a 256) | tee "$s.sha256"
  du -sh "$s"
}

stage_export() {
  local arm=${1:?export <D|E>} run=$WORK/runs/$1
  v8_file "$arm" >/dev/null
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

long5_corpora() { # long5 is v8 dev (as in R6): both halves in one corpus, the R5 attack documents in another
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
  local name=${1:?gates <name> [model dir]} l2; l2=${2:-$(model_dir "$1")}
  [ -f "$l2/calibration.json" ] || { echo "no $l2/calibration.json (export first)" >&2; exit 1; }
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
  for n in $ARMS ref v6rel; do
    args+=(--model "$n=$(model_dir "$n")" --benign "$n=$WORK/dumps/$n/benign" --attack "$n=$WORK/dumps/$n/attack")
  done
  $UV python longdoc_v8.py --stage dev --out "$WORK/select" "${args[@]}"
  local arms; arms=$(echo "$ARMS" | tr ' ' ',')
  $UV python select_v8.py --arms "$arms" --ref ref --gates "$WORK/gates" --longdoc "$WORK/select/v8_dev_longdoc.json" \
    --runs "$WORK/runs" --out "$TRAIN/reports/v8_dev.json"
}

dev_committed() { # long7 is opened only after reports/v8_dev.json is committed unchanged
  local f=train/reports/v8_dev.json
  if ! git -C "$REPO" ls-files --error-unmatch "$f" >/dev/null 2>&1 || ! git -C "$REPO" diff --quiet HEAD -- "$f"; then
    echo "commit $f before scoring long7" >&2; exit 1
  fi
}

holdout_models() { # the chosen arm (or the fallback candidate), ref and the released v6
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["decision"]; print(d.get("chosen") or d["fallback_candidate"], "ref v6rel")' \
    "$TRAIN/reports/v8_dev.json"
}

stage_holdout() {
  local name=${1:?holdout <name>} l2
  dev_committed
  case " $(holdout_models) " in *" $name "*) ;; *) echo "$name is not scored on long7 (pre-registered: $(holdout_models))" >&2; exit 1 ;; esac
  l2=$(model_dir "$name")
  bins
  longpath "$LONG7_BENIGN" "$WORK/long7/$name/benign" "$l2" "long7-$name"
  longpath "$LONG7_ATTACK" "$WORK/long7/$name/attack" "$l2" "long7-attack-$name"
}

stage_holdout_report() {
  local args=() n
  dev_committed
  for n in $(holdout_models); do
    args+=(--model "$n=$(model_dir "$n")" --benign "$n=$WORK/long7/$n/benign" --attack "$n=$WORK/long7/$n/attack")
  done
  $UV python longdoc_v8.py --stage holdout --out "$WORK/long7" "${args[@]}"
}

case ${1:-} in
  stage) stage_stage "${2:-}" ;;
  export) stage_export "${2:-}" ;;
  refs) stage_refs ;;
  gates) stage_gates "${2:-}" "${3:-}" ;;
  select) stage_select ;;
  holdout) stage_holdout "${2:-}" ;;
  holdout-report) stage_holdout_report ;;
  *) echo "usage: $0 stage|export <D|E> | gates <name> [dir] | holdout <name> | refs | select | holdout-report" >&2; exit 2 ;;
esac
