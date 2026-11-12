#!/usr/bin/env bash
# v6 arms (RF-895d3533 R2): train A, B and C one after the other on the v6 data, export and calibrate
# each, score the dev gates G1-G7 and apply the pre-registered rule (MODEL_CARD.md, v6). Every stage is
# resumable: run the script again after an interruption and it skips what is done (a training run
# continues from its last finished epoch, train.py --resume). Nothing runs in parallel: one training,
# one benchmark at a time (the owner's laptop).
#
#   cd train && GUARD_V6_OUT=... GUARD_DATA_V4A=... BENCH_CACHE=... ./run_arms_v6.sh [all|data|train|gates|select]
#   ./run_arms_v6.sh holdout <arm>     # once, after the decision: hold-outs of the chosen arm, v3b and v5
#   ./run_arms_v6.sh package <arm>     # the five files + SHA256SUMS under $GUARD_V6_RELEASE
#
# Arms (the v5 recipe, window-level training, same seed and settings; validation identical in every arm:
# the v4-A build's validation files plus v6_val and val_v6):
#   A = v4-A training data (owner batch 1 + 2) + v6_train
#   B = A with the benign twins (kind twin) twice per epoch
#   C = A with the security hard negatives (kinds secdoc_en, secprose_en, secprose_vi) twice per epoch
#
# Environment (paths outside the repository; owner rows are never written into git):
#   GUARD_V6_OUT             data/build_v6.py output (v6_train, v6_val, val_v6; val_v6_holdout is never read
#                            before the holdout stage)
#   GUARD_DATA_V4A           an existing v4-A build (run_arms_v5.sh data-v4A); without it the build runs as
#                            in run_arms_v5.sh (GUARD_OWNER_TRAIN_V4, GUARD_OWNER_HOLDOUT_V4, GUARD_OTPKYC_*)
#   BENCH_CACHE              bench/long corpus cache: $BENCH_CACHE/long/full/docs.jsonl (and long/quick)
#   GUARD_V5_OUT             the v5 build (val_v5_holdout; holdout stage only)
#   GUARD_V5_PACKAGE         the packaged v5 classifier (holdout stage: scored next to v3b and the arm)
#   GUARD_BENCH_V3B_FULL     an existing v3b full-profile benchlong report to copy (optional; v3b has no cap,
#                            so a report from the same corpus and code is unchanged)
#   GUARD_V6_RELEASE         package directory (package stage; default $GUARD_V6_WORK/release)
#   GUARD_V6_WORK            working directory (default train/runs/v6, gitignored)
#   ARMS                     arms to train (default "A B C")
#   BENCH_WORKERS            documents scored in parallel by cmd/benchlong (default 4, as the baselines)
#
# Outputs: $GUARD_V6_WORK/{data-v4A,A,B,C,gates,holdout,logs} and reports/train_arms_v6.json (aggregate
# numbers only). The gates stage needs Go, the onnx build deps (make onnx-deps), the L3 model
# (models/cache/multilingual-e5-small), v3b (models/local/guardspec-classifier-v3b) and the bench/long
# full corpus; without them it stops and the report says "gates pending".
set -euo pipefail

TRAIN=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$TRAIN/.." && pwd)
cd "$TRAIN"

: "${GUARD_V6_OUT:?set GUARD_V6_OUT to the data/build_v6.py output directory}"
WORK=${GUARD_V6_WORK:-$TRAIN/runs/v6}
ARMS=${ARMS:-"A B C"}
STAGE=${1:-all}
BENCH=${BENCH_CACHE:-$REPO/bench/.cache}
mkdir -p "$WORK/logs"
LOG="$WORK/logs"
UV="uv run --frozen"
V4A=$WORK/data-v4A
V3B=$REPO/models/local/guardspec-classifier-v3b

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG/run.log"; }

for f in v6_train.jsonl v6_val.jsonl val_v6.jsonl; do
  [ -f "$GUARD_V6_OUT/$f" ] || { echo "missing $GUARD_V6_OUT/$f" >&2; exit 1; }
done

export CGO_LDFLAGS="-L$REPO/.onnx/lib" ONNXRUNTIME_LIB="${ONNXRUNTIME_LIB:-$REPO/.onnx/lib/libonnxruntime.dylib}"

val_files() { # the validation files of every arm, comma-separated (calibration)
  local v
  v=$(printf '%s,' "$V4A"/{val,val_hard,val_vi_variants,val_v3,val_v4}.jsonl "$GUARD_V6_OUT"/{v6_val,val_v6}.jsonl)
  echo "${v%,}"
}

# ------------------------------------------------------------------ data
stage_data() {
  if [ ! -e "$V4A" ]; then
    if [ -n "${GUARD_DATA_V4A:-}" ]; then
      [ -f "$GUARD_DATA_V4A/train.jsonl" ] || { echo "GUARD_DATA_V4A=$GUARD_DATA_V4A has no train.jsonl" >&2; exit 1; }
      say "data: using the v4-A build $GUARD_DATA_V4A"
      ln -s "$GUARD_DATA_V4A" "$V4A"
    else
      : "${GUARD_OWNER_TRAIN_V4:?}" "${GUARD_OWNER_HOLDOUT_V4:?}"
      if [ -z "${GUARD_OTPKYC_TRAIN:-}" ] && [ "${GUARD_ALLOW_NO_OTPKYC:-0}" != 1 ]; then
        echo "GUARD_OTPKYC_TRAIN / GUARD_OTPKYC_PROBE unset: v4-A used them (GUARD_ALLOW_NO_OTPKYC=1 to go on)" >&2
        exit 1
      fi
      say "data: building $V4A"
      GUARD_V4_DATA=1 GUARD_OWNER_TRAIN=$GUARD_OWNER_TRAIN_V4 GUARD_OWNER_HOLDOUT=$GUARD_OWNER_HOLDOUT_V4 GUARD_BUILD_OUT=$V4A \
        GUARD_OTPKYC_TRAIN=${GUARD_OTPKYC_TRAIN:-} GUARD_OTPKYC_PROBE=${GUARD_OTPKYC_PROBE:-} \
        $UV python data/build_data.py 2>&1 | tee -a "$LOG/data.log"
      touch "$V4A/.done"
    fi
  else
    say "data: $V4A present"
  fi
  # No training text (v4-A train, v6_train) may be a validation text (v4-A validation files, v6_val, val_v6).
  $UV python - "$V4A/train.jsonl" "$GUARD_V6_OUT/v6_train.jsonl" -- "$V4A"/val*.jsonl "$GUARD_V6_OUT/v6_val.jsonl" "$GUARD_V6_OUT/val_v6.jsonl" <<'EOF'
import json, sys
i = sys.argv.index("--")
train = {json.loads(l)["text"] for p in sys.argv[1:i] for l in open(p, encoding="utf-8")}
bad = {p: sum(json.loads(l)["text"] in train for l in open(p, encoding="utf-8")) for p in sys.argv[i + 1:]}
bad = {p: n for p, n in bad.items() if n and not p.endswith("_holdout.jsonl")}
if bad:
    sys.exit(f"training rows in the validation files: {bad}")
print("overlap check: no training text in the validation files")
EOF
}

# ------------------------------------------------------------------ train
arm_args() {
  case $1 in
    A) echo "" ;;
    B) echo "--oversample-kind twin=2" ;;
    C) echo "--oversample-kind secdoc_en=2 --oversample-kind secprose_en=2 --oversample-kind secprose_vi=2" ;;
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
    $UV python train.py --data-dir "$V4A" --v6-dir "$GUARD_V6_OUT" $(arm_args "$arm") --run-dir "$WORK/$arm" --resume \
      2>&1 | tee -a "$LOG/train_$arm.log"
    say "train: arm $arm finished"
  done
}

arm_flags() { for arm in $ARMS; do printf -- '--arm %s=%s ' "$arm" "$WORK/$arm"; done; }

stage_select() {
  # shellcheck disable=SC2046
  $UV python select_v6.py $(arm_flags) --gates "$WORK/gates" --out "$TRAIN/reports/train_arms_v6.json" \
    2>&1 | tee -a "$LOG/select.log"
}

# ------------------------------------------------------------------ eval helpers
# run_eval <out.json> <l2 dir or ""> <data dir> <path> [extra flags]: cmd/eval -json (fusion-ml, or L1 only
# without an L2 dir). Skipped when the output exists.
run_eval() {
  local out=$1 l2=$2 data=$3 path=$4; shift 4
  [ -f "$out" ] && return 0
  mkdir -p "$(dirname "$out")"
  say "eval: $(basename "$(dirname "$out")")/$(basename "$out" .json) ($data, $path $*)"
  if [ -z "$l2" ]; then
    (cd "$REPO" && go run ./cmd/eval -data "$data" -path "$path" -json "$out.tmp" "$@") >>"$LOG/eval.log" 2>&1
  else
    (cd "$REPO" && L2_MODEL_DIR=$l2 go run -tags onnx ./cmd/eval -detector fusion-ml -data "$data" -path "$path" \
      -json "$out.tmp" "$@") >>"$LOG/eval.log" 2>&1
  fi
  mv "$out.tmp" "$out"
}

# run_bench <out.json> <l2 dir> <profile>: cmd/benchlong score pass with the model's calibration and cap.
run_bench() {
  local out=$1 l2=$2 profile=$3
  [ -f "$out" ] && return 0
  [ -f "$BENCH/long/$profile/docs.jsonl" ] || { echo "no bench/long $profile corpus under $BENCH (make bench-long PROFILE=$profile)" >&2; exit 1; }
  mkdir -p "$(dirname "$out")"
  say "bench: $(basename "$(dirname "$out")")/$(basename "$out" .json) ($profile)"
  (cd "$REPO" && L2_MODEL_DIR=$l2 go run -tags onnx ./cmd/benchlong -corpus "$BENCH/long/$profile" -profile "$profile" \
    -layers "l1;l1,l2" -skip-latency -workers "${BENCH_WORKERS:-4}" -l2cap on -out "$out.tmp.json") >>"$LOG/bench.log" 2>&1
  mv "$out.tmp.json" "$out"
  mv "$out.tmp.md" "${out%.json}.md"
}

# g5_data: val_v3 of the v4-A build in the eval-set row format (the G5 input), under $WORK/g5.
g5_data() {
  if [ ! -f "$WORK/g5/val_v3/val_v3.jsonl" ]; then
    $UV python holdout_evalset.py --data-dir "$V4A" --split-file "val_v3=$V4A/val_v3.jsonl" --splits val_v3 \
      --out "$WORK/g5/val_v3" >>"$LOG/eval.log" 2>&1
  fi
  echo "$WORK/g5/val_v3"
}

# ------------------------------------------------------------------ gates
stage_gates() {
  if [ ! -f "$REPO/eval/embedded/embedded.jsonl" ] || ! grep -q '"corroboration"' "$REPO/cmd/eval/main.go"; then
    say "gates: eval/embedded or cmd/eval -corroboration missing; gates pending"
    return 0
  fi
  local G=$WORK/gates
  for arm in $ARMS; do
    local model=$WORK/$arm/model
    if [ ! -f "$model/calibration.json" ]; then
      say "gates: export + calibrate arm $arm"
      $UV python export.py --data-dir "$V4A" --v6-dir "$GUARD_V6_OUT" --run-dir "$WORK/$arm" --out-dir "$model" \
        2>&1 | tee -a "$LOG/export_$arm.log"
      (cd "$REPO" && go run -tags onnx ./cmd/calibrate fit -write -l2 "$model" -val "$(val_files)") 2>&1 | tee -a "$LOG/calibrate_$arm.log"
    fi
  done
  local g5
  g5=$(g5_data)
  for name in v3b $ARMS; do
    local l2=$WORK/$name/model
    [ "$name" = v3b ] && l2=$V3B
    run_eval "$G/$name/eval.json" "$l2" eval/data direct
    run_eval "$G/$name/codelog.json" "$l2" eval/codelog tool -corroboration off
    run_eval "$G/$name/embedded.json" "$l2" eval/embedded tool -corroboration off
    run_eval "$G/$name/val_v3.json" "$l2" "$g5" direct
  done
  run_eval "$G/l1/embedded.json" "" eval/embedded tool
  if [ -n "${GUARD_BENCH_V3B_FULL:-}" ] && [ ! -f "$G/v3b/benchlong-full.json" ]; then
    cp "$GUARD_BENCH_V3B_FULL" "$G/v3b/benchlong-full.json"
  fi
  for arm in $ARMS; do
    run_bench "$G/$arm/benchlong-full.json" "$WORK/$arm/model" full
  done
}

# ------------------------------------------------------------------ hold-outs (once, after the decision)
stage_holdout() {
  local arm=${1:?holdout <arm>}
  local H=$WORK/holdout G=$WORK/gates
  if [ ! -f "$H/data/.done" ]; then
    say "holdout: writing the hold-out splits"
    # shellcheck disable=SC2086
    $UV python holdout_evalset.py --data-dir "$V4A" ${GUARD_V5_OUT:+--v5-dir "$GUARD_V5_OUT"} --v6-dir "$GUARD_V6_OUT" \
      --out "$H/data" 2>&1 | tee -a "$LOG/holdout.log"
    for f in "$H"/data/*.jsonl; do  # one directory per split, so every cmd/eval report is one split
      local n; n=$(basename "$f" .jsonl)
      mkdir -p "$H/data/$n" && mv "$f" "$H/data/$n/"
    done
    touch "$H/data/.done"
  fi
  local models="v3b=$V3B $arm=$WORK/$arm/model"
  [ -n "${GUARD_V5_PACKAGE:-}" ] && models="$models v5=$GUARD_V5_PACKAGE"
  for m in $models; do
    local name=${m%%=*} l2=${m#*=}
    for sp in val_v3_holdout val_realistic_holdout val_v4_holdout user_holdout probe_v4 otpkyc_probe; do
      [ -d "$H/data/$sp" ] && run_eval "$H/$name/$sp.json" "$l2" "$H/data/$sp" direct
    done
    for sp in val_v5_holdout val_v6_holdout; do
      [ -d "$H/data/$sp" ] || continue
      run_eval "$H/$name/$sp.json" "$l2" "$H/data/$sp" tool -corroboration off
      run_eval "$H/$name/$sp.on.json" "$l2" "$H/data/$sp" tool -corroboration on
    done
    # eval/ hold-out halves: the dev-gate reports carry slices.holdout; corroboration on is a second run.
    run_eval "$H/$name/eval.json" "$l2" eval/data direct
    run_eval "$H/$name/codelog.json" "$l2" eval/codelog tool -corroboration off
    run_eval "$H/$name/codelog.on.json" "$l2" eval/codelog tool -corroboration on
    run_eval "$H/$name/embedded.json" "$l2" eval/embedded tool -corroboration off
    run_eval "$H/$name/embedded.on.json" "$l2" eval/embedded tool -corroboration on
  done
  for sp in eval codelog embedded; do  # the arm's and v3b's dev-gate reports are the same runs
    for name in v3b $arm; do
      [ -f "$H/$name/$sp.json" ] || cp "$G/$name/$sp.json" "$H/$name/$sp.json"
    done
  done
  # bench/long: the arm's full report (gates) holds the hold-out rows; v5 is scored again with its cap
  # (the baselines of 2026-11-11 ran before cmd/benchlong applied it); the quick profile is recorded.
  [ -n "${GUARD_V5_PACKAGE:-}" ] && run_bench "$H/v5/benchlong-full.json" "$GUARD_V5_PACKAGE" full
  run_bench "$H/$arm/benchlong-quick.json" "$WORK/$arm/model" quick
  say "holdout: done for $arm"
}

# ------------------------------------------------------------------ package
stage_package() {
  local arm=${1:?package <arm>}
  local src=$WORK/$arm/model dst=${GUARD_V6_RELEASE:-$WORK/release}/guardspec-classifier-v6
  mkdir -p "$dst"
  for f in model_int8.onnx tokenizer.json config.json; do cp "$src/$f" "$dst/$f"; done
  $UV python - "$src" "$dst" "$(val_files)" <<'EOF'
import json, sys
from pathlib import Path
src, dst, vals = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3].split(",")
for name in ("thresholds.json", "calibration.json"):
    d = json.loads((src / name).read_text(encoding="utf-8"))
    d["model"] = "guardspec-classifier-v6"
    if name == "calibration.json":
        n = d["fitted_on"].split("(")[-1]
        d["fitted_on"] = ("v4-A build val.jsonl + val_hard.jsonl + val_vi_variants.jsonl + val_v3.jsonl + val_v4.jsonl, with the "
                          "owner-supplied and OTP/KYC validation rows, plus v6_val.jsonl + val_v6.jsonl of the v6 build (" + n)
    (dst / name).write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
EOF
  (cd "$dst" && shasum -a 256 model_int8.onnx tokenizer.json config.json thresholds.json calibration.json > SHA256SUMS && shasum -a 256 -c SHA256SUMS)
  say "package: $dst"
}

case $STAGE in
  data) stage_data ;;
  train) stage_train ;;
  gates) stage_gates ;;
  select) stage_select ;;
  holdout) stage_holdout "${2:-}" ;;
  package) stage_package "${2:-}" ;;
  all) stage_data; stage_train; stage_gates; stage_select ;;
  *) echo "usage: $0 [all|data|train|gates|select|holdout <arm>|package <arm>]" >&2; exit 2 ;;
esac
