#!/usr/bin/env bash
# v5 arms (RF-437128e9): build the arm data, train A, B and C one after the other, score the
# gates and apply the pre-registered rule (MODEL_CARD.md, v5). Every stage is resumable: run the
# script again after an interruption and it skips what is done (a training run continues from its
# last finished epoch, train.py --resume).
#
#   cd train && GUARD_V5_OUT=... GUARD_OWNER_TRAIN_V3B=... ./run_arms_v5.sh [all|data|train|select|gates]
#
# Arms (same recipe as v3b/v4; validation identical in every arm: the v4-A build's validation files
# plus v5_val and val_v5):
#   A = v3b training data + v5_train
#   B = v4-A training data + v5_train
#   C = A with the repeated-line hard negatives (kind log_vi_repeat) twice per epoch
#
# Environment (paths outside the repository; owner rows are never written into git):
#   GUARD_V5_OUT             data/build_v5.py output (v5_train, v5_val, val_v5; val_v5_holdout is never read)
#   GUARD_OWNER_TRAIN_V3B    owner batch 1 training rows (user_train.jsonl)     -> v3b data
#   GUARD_OWNER_HOLDOUT_V3B  owner batch 1 hold-out (user_holdout.jsonl)        -> v3b data (leakage guard only)
#   GUARD_OWNER_TRAIN_V4     owner batch 1 + 2 training rows (user2_train.jsonl) -> v4-A data
#   GUARD_OWNER_HOLDOUT_V4   owner batch 1 + 2 hold-out (user2_holdout.jsonl)   -> v4-A data (leakage guard only)
#   GUARD_OTPKYC_TRAIN, GUARD_OTPKYC_PROBE   OTP/KYC rows of v3b and v4-A (GUARD_ALLOW_NO_OTPKYC=1 to go without)
#   GUARD_V5_WORK            working directory (default train/runs/v5, gitignored)
#   ARMS                     arms to train (default "A B C")
#
# Outputs: $GUARD_V5_WORK/{data-v3b,data-v4A,A,B,C,gates,logs} and reports/train_arms_v5.json
# (aggregate numbers only). The gates stage needs Go, the onnx build deps (make onnx-deps), the L3
# model (models/cache/multilingual-e5-small), v3b (models/local/guardspec-classifier-v3b), and the
# eval/embedded set with cmd/eval -corroboration (RF-437128e9 T1); without them it stops and the
# report says "gates pending".
set -euo pipefail

TRAIN=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$TRAIN/.." && pwd)
cd "$TRAIN"

: "${GUARD_V5_OUT:?set GUARD_V5_OUT to the data/build_v5.py output directory}"
WORK=${GUARD_V5_WORK:-$TRAIN/runs/v5}
ARMS=${ARMS:-"A B C"}
STAGE=${1:-all}
mkdir -p "$WORK/logs"
LOG="$WORK/logs"
UV="uv run --frozen"

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG/run.log"; }

for f in v5_train.jsonl v5_val.jsonl val_v5.jsonl; do
  [ -f "$GUARD_V5_OUT/$f" ] || { echo "missing $GUARD_V5_OUT/$f" >&2; exit 1; }
done

# ------------------------------------------------------------------ data
build() { # build <out> <owner train> <owner holdout> <v4 data 0|1>
  local out=$1
  if [ -f "$out/.done" ]; then say "data: $out done"; return; fi
  if [ -z "${GUARD_OTPKYC_TRAIN:-}" ] && [ "${GUARD_ALLOW_NO_OTPKYC:-0}" != 1 ]; then
    echo "GUARD_OTPKYC_TRAIN / GUARD_OTPKYC_PROBE unset: v3b and v4-A used them (GUARD_ALLOW_NO_OTPKYC=1 to go on)" >&2
    exit 1
  fi
  say "data: building $out"
  GUARD_V4_DATA=$4 GUARD_OWNER_TRAIN=$2 GUARD_OWNER_HOLDOUT=$3 GUARD_BUILD_OUT=$out \
    GUARD_OTPKYC_TRAIN=${GUARD_OTPKYC_TRAIN:-} GUARD_OTPKYC_PROBE=${GUARD_OTPKYC_PROBE:-} \
    $UV python data/build_data.py 2>&1 | tee -a "$LOG/data.log"
  touch "$out/.done"
}

stage_data() {
  : "${GUARD_OWNER_TRAIN_V3B:?}" "${GUARD_OWNER_HOLDOUT_V3B:?}" "${GUARD_OWNER_TRAIN_V4:?}" "${GUARD_OWNER_HOLDOUT_V4:?}"
  build "$WORK/data-v3b" "$GUARD_OWNER_TRAIN_V3B" "$GUARD_OWNER_HOLDOUT_V3B" 0
  build "$WORK/data-v4A" "$GUARD_OWNER_TRAIN_V4" "$GUARD_OWNER_HOLDOUT_V4" 1
  # Arm A trains on the v3b training split but validates on the v4-A validation files (identical
  # validation in every arm): no training text may be a validation text.
  $UV python - "$WORK/data-v3b/train.jsonl" "$WORK"/data-v4A/val*.jsonl "$GUARD_V5_OUT/v5_val.jsonl" "$GUARD_V5_OUT/val_v5.jsonl" <<'EOF'
import json, sys
train = {json.loads(l)["text"] for l in open(sys.argv[1], encoding="utf-8")}
bad = {p: sum(json.loads(l)["text"] in train for l in open(p, encoding="utf-8")) for p in sys.argv[2:]}
bad = {p: n for p, n in bad.items() if n and not p.endswith("_holdout.jsonl")}
if bad:
    sys.exit(f"v3b training rows in the validation files: {bad}")
print("overlap check: no v3b training text in the validation files")
EOF
}

# ------------------------------------------------------------------ train
arm_args() {
  case $1 in
    A) echo "--data-dir $WORK/data-v4A --train $WORK/data-v3b/train.jsonl" ;;
    B) echo "--data-dir $WORK/data-v4A" ;;
    C) echo "--data-dir $WORK/data-v4A --train $WORK/data-v3b/train.jsonl --oversample-kind log_vi_repeat=2" ;;
    *) echo "unknown arm $1" >&2; exit 1 ;;
  esac
}

stage_train() {
  for arm in $ARMS; do
    if [ -f "$WORK/$arm/train_log.json" ] && [ -f "$WORK/$arm/val_scores.jsonl" ]; then
      say "train: arm $arm done"; continue
    fi
    say "train: arm $arm start"
    # shellcheck disable=SC2046
    $UV python train.py $(arm_args "$arm") --v5-dir "$GUARD_V5_OUT" --run-dir "$WORK/$arm" --resume \
      2>&1 | tee -a "$LOG/train_$arm.log"
    say "train: arm $arm finished"
  done
}

arm_flags() { for arm in $ARMS; do printf -- '--arm %s=%s ' "$arm" "$WORK/$arm"; done; }

stage_select() {
  # shellcheck disable=SC2046
  $UV python select_v5.py $(arm_flags) --gates "$WORK/gates" --out "$TRAIN/reports/train_arms_v5.json" \
    2>&1 | tee -a "$LOG/select.log"
}

# ------------------------------------------------------------------ gates
stage_gates() {
  if [ ! -f "$REPO/eval/embedded/embedded.jsonl" ] || ! grep -q '"corroboration"' "$REPO/cmd/eval/main.go"; then
    say "gates: eval/embedded or cmd/eval -corroboration missing (merge RF-437128e9 T1 first); gates pending"
    return 0
  fi
  local G=$WORK/gates
  local val
  val=$(printf '%s,' "$WORK"/data-v4A/{val,val_hard,val_vi_variants,val_v3,val_v4}.jsonl "$GUARD_V5_OUT"/{v5_val,val_v5}.jsonl)
  val=${val%,}
  export CGO_LDFLAGS="-L$REPO/.onnx/lib" ONNXRUNTIME_LIB="${ONNXRUNTIME_LIB:-$REPO/.onnx/lib/libonnxruntime.dylib}"
  for arm in $ARMS; do
    local model=$WORK/$arm/model
    if [ ! -f "$model/calibration.json" ]; then
      say "gates: export + calibrate arm $arm"
      $UV python export.py --data-dir "$WORK/data-v4A" --v5-dir "$GUARD_V5_OUT" --run-dir "$WORK/$arm" --out-dir "$model" \
        2>&1 | tee -a "$LOG/export_$arm.log"
      (cd "$REPO" && go run -tags onnx ./cmd/calibrate fit -write -l2 "$model" -val "$val") 2>&1 | tee -a "$LOG/calibrate_$arm.log"
    fi
  done
  run_eval() { # run_eval <name> <l2 dir or ""> <set> [extra flags]
    local name=$1 l2=$2 set=$3; shift 3
    local out=$G/$name/$set.json
    [ -f "$out" ] && return 0
    mkdir -p "$G/$name"
    say "gates: $name $set"
    local data=eval/data path=direct
    case $set in codelog) data=eval/codelog path=tool ;; embedded) data=eval/embedded path=tool ;; esac
    if [ -z "$l2" ]; then
      (cd "$REPO" && go run ./cmd/eval -data "$data" -path "$path" -json "$out.tmp" "$@") >>"$LOG/gates.log" 2>&1
    else
      (cd "$REPO" && L2_MODEL_DIR=$l2 go run -tags onnx ./cmd/eval -detector fusion-ml -data "$data" -path "$path" \
        -json "$out.tmp" "$@") >>"$LOG/gates.log" 2>&1
    fi
    mv "$out.tmp" "$out"
  }
  for name in v3b $ARMS; do
    local l2=$WORK/$name/model
    [ "$name" = v3b ] && l2=$REPO/models/local/guardspec-classifier-v3b
    run_eval "$name" "$l2" eval
    run_eval "$name" "$l2" codelog -corroboration off
    run_eval "$name" "$l2" embedded -corroboration off
  done
  run_eval l1 "" embedded
}

case $STAGE in
  data) stage_data ;;
  train) stage_train ;;
  gates) stage_gates ;;
  select) stage_select ;;
  all) stage_data; stage_train; stage_select; stage_gates; stage_select ;;
  *) echo "usage: $0 [all|data|train|select|gates]" >&2; exit 2 ;;
esac
