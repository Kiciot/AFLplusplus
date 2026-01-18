#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
COMMON="$SCRIPT_DIR/common.sh"

if [[ ! -f "$COMMON" ]]; then
  echo "missing common.sh" >&2
  exit 1
fi

source "$COMMON"

AFL_BIN=${AFL_BIN:-$ROOT_DIR/afl-fuzz}
OUT_ROOT="${OUT_ROOT:-/tmp/afl-regression}"
TARGET_SRC="$SCRIPT_DIR/toy/target.c"
TARGET_BIN="$SCRIPT_DIR/toy/target"
IN_DIR="$SCRIPT_DIR/toy/inputs"
SECONDS_RUN=${SECONDS_RUN:-60}

rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT"

echo "[*] Building toy target..."
cc -O2 -g "$TARGET_SRC" -o "$TARGET_BIN"

run_once() {
  local mode=$1
  local out_dir="$OUT_ROOT/$mode"
  local extra_env=$2
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  echo "[*] Running $mode for ${SECONDS_RUN}s..."
  env AFL_EXIT_ON_TIME=$SECONDS_RUN $extra_env \
    "$AFL_BIN" -i "$IN_DIR" -o "$out_dir" -- "$TARGET_BIN" @@ >/dev/null
  wait_for_stats "$out_dir/fuzzer_stats"
  collect_stats_line "$mode" "$mode" "$SECONDS_RUN" "$out_dir/fuzzer_stats" \
    "$OUT_ROOT/regression.csv" 0
}

write_header_once "$OUT_ROOT/regression.csv" "$STATS_HEADER"

run_once baseline "AFL_BANDIT=0"
run_once bandit "AFL_BANDIT=1 AFL_BANDIT_REWARD=rarity_mass"

echo "[*] Results in $OUT_ROOT/regression.csv"
echo "[*] execs_per_sec baseline vs bandit:"
awk -F',' 'NR==1{next} {print $1 ": " $5 " exec/s"}' "$OUT_ROOT/regression.csv"
