#!/usr/bin/env bash
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# R8a (RF-35fd836c, reports/r8a_preregistration.md): R7's arm E under strong75_l2 on the long8 holdout.
# No training. Everything runs on the laptop, ONNX INT8 on the CPU, one heavy job at a time.
#
#   ./run_r8a.sh holdout <E|v6rel>   # long8 benign + attack documents through the long path, once per model
#   ./run_r8a.sh report              # longdoc_r8a.py holdout + verdict_r8a.py -> reports/r8a_holdout.json
#
# Environment: GUARD_DATA (default ~/WorkingSpace/AI_R_D/guardspec-data), BENCH_CACHE (bench/long corpora,
# long8 among them), GUARD_LONG8_ATTACK (the long8 embedded-attack documents).
set -euo pipefail

TRAIN=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$TRAIN/.." && pwd)
D=${GUARD_DATA:-$HOME/WorkingSpace/AI_R_D/guardspec-data}
V8=$D/v8/work
OUT=${GUARD_R8A_WORK:-$D/v8/r8a}
BENCH=${BENCH_CACHE:-$D/v6/bench-cache}/long
LONG8_BENIGN=${GUARD_LONG8_BENIGN:-$BENCH/long8}
LONG8_ATTACK=${GUARD_LONG8_ATTACK:-$D/v8/long8/attack}
MODELS="E v6rel" # pre-registered; nothing else is scored on long8
UV="uv run --frozen"
mkdir -p "$OUT/logs"
say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$OUT/logs/run.log"; }
export CGO_LDFLAGS="-L$REPO/.onnx/lib" ONNXRUNTIME_LIB="${ONNXRUNTIME_LIB:-$REPO/.onnx/lib/libonnxruntime.dylib}"

model_dir() {
  case $1 in
    E) echo "$V8/runs/E/model" ;;
    v6rel) echo "${GUARD_V6_RELEASE:-$D/v6/release/guardspec-classifier-v6}" ;;
    *) echo "$1 is not scored on long8 (pre-registered: $MODELS)" >&2; exit 1 ;;
  esac
}

pinned() { # long8 is scored only once it is pinned, after the pre-registration, and its files match the pins
  local f
  for f in train/reports/r8a_preregistration.md bench/long/corpus.yaml; do
    if ! git -C "$REPO" ls-files --error-unmatch "$f" >/dev/null 2>&1 || ! git -C "$REPO" diff --quiet HEAD -- "$f"; then
      echo "commit $f before scoring long8" >&2; exit 1
    fi
  done
  $UV python - "$REPO/bench/long/corpus.yaml" "$LONG8_BENIGN/docs.jsonl" "$LONG8_ATTACK/docs.jsonl" <<'EOF'
import hashlib, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
want = (cfg.get("outputs") or {}).get("long8")
if not want:
    sys.exit("corpus.yaml has no outputs.long8 pin")
got = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
if got != want:
    sys.exit(f"long8 docs.jsonl is {got}, corpus.yaml pins {want}")
att = hashlib.sha256(open(sys.argv[3], "rb").read()).hexdigest()
if att not in open(sys.argv[1], encoding="utf-8").read():
    sys.exit(f"the long8 attack documents ({att}) are not pinned in corpus.yaml")
EOF
}

bins() { # one build of each tool per commit
  local c; c=$(git -C "$REPO" rev-parse --short HEAD)
  BIN=$OUT/bin/$c
  if [ ! -x "$BIN/benchlong" ]; then
    mkdir -p "$BIN"
    (cd "$REPO" && go build -tags onnx -o "$BIN/benchlong" ./cmd/benchlong && go build -tags onnx -o "$BIN/eval" ./cmd/eval)
  fi
}

longpath() { # <corpus dir> <dump prefix> <l2 dir> <label>; never overwrites: each model is scored once
  local corpus=$1 dump=$2 l2=$3 label=$4
  if [ -f "$dump.json" ] || [ -f "$dump.log" ]; then
    echo "$dump already scored (or started): long8 is scored once per model" >&2; exit 1
  fi
  mkdir -p "$(dirname "$dump")"
  say "long path start: $dump"
  (cd "$REPO" && L2_MODEL_DIR=$l2 "$BIN/benchlong" -corpus "$corpus" -profile "$label" -layers none -l2pass off -long on \
    -dump "$dump" -skip-latency -workers "${BENCH_WORKERS:-4}" -host "m3max-$label" -out "$dump.tmp.json") >"$dump.log" 2>&1
  mv "$dump.tmp.json" "$dump.json"; mv "$dump.tmp.md" "$dump.md"
  say "long path end: $dump"
}

stage_holdout() {
  local name=${1:?holdout <E|v6rel>} l2
  l2=$(model_dir "$name")
  pinned
  bins
  longpath "$LONG8_BENIGN" "$OUT/long8/$name/benign" "$l2" "long8-$name"
  longpath "$LONG8_ATTACK" "$OUT/long8/$name/attack" "$l2" "long8-attack-$name"
}

stage_report() {
  local args=() n
  pinned
  for n in $MODELS; do
    args+=(--model "$n=$(model_dir "$n")" --benign "$n=$OUT/long8/$n/benign" --attack "$n=$OUT/long8/$n/attack")
  done
  $UV python longdoc_r8a.py --stage holdout --out "$OUT/long8" "${args[@]}"
  # E's eval/data hold-out slice: the R7 dev-stage cmd/eval report, read here for the first time.
  $UV python verdict_r8a.py --longdoc "$OUT/long8/r8a_holdout_longdoc.json" --eval "$V8/gates/E/eval.json" \
    --log "$OUT/logs/run.log" --out "$TRAIN/reports/r8a_holdout.json"
}

case ${1:-} in
  holdout) stage_holdout "${2:-}" ;;
  report) stage_report ;;
  *) echo "usage: $0 holdout <E|v6rel> | report" >&2; exit 2 ;;
esac
