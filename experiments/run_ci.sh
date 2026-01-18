#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'USAGE'
Usage: run_ci.sh -i <in_dir> -o <out_root> [-- <target> [args...]]

Defaults:
  durations: 3600 and 14400 seconds
  sample interval: 60 seconds

Environment:
  AFL_BIN        Path to afl-fuzz (default: repo_root/afl-fuzz)
  CI_SHORT=1     Use 300/900 seconds instead of 1h/4h
  AFL_BANDIT_*   Bandit config variables passed through for bandit runs
USAGE
}

IN_DIR=""
OUT_ROOT=""

while getopts ":i:o:h" opt; do
  case "$opt" in
    i) IN_DIR="$OPTARG" ;;
    o) OUT_ROOT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

if [[ -z "$IN_DIR" || -z "$OUT_ROOT" || $# -lt 1 ]]; then
  usage
  exit 1
fi

AFL_BIN=${AFL_BIN:-$AFL_BIN_DEFAULT}
INTERVAL=${INTERVAL:-60}

if [[ "${CI_SHORT:-0}" -eq 1 ]]; then
  DURATIONS=(300 900)
else
  DURATIONS=(3600 14400)
fi

STATS_CSV="$OUT_ROOT/stats.csv"
COVERAGE_CSV="$OUT_ROOT/coverage.csv"

mkdir -p "$OUT_ROOT"
write_header_once "$STATS_CSV" "$STATS_HEADER"
write_header_once "$COVERAGE_CSV" "$COVERAGE_HEADER"

run_one() {
  local mode=$1
  local seconds=$2
  local run_id=$3
  local run_dir="$OUT_ROOT/${mode}-${run_id}-${seconds}s"

  mkdir -p "$run_dir"

  export AFL_EXIT_ON_TIME="$seconds"
  if [[ "$mode" == "bandit" ]]; then
    : "${AFL_BANDIT:=1}"
    export AFL_BANDIT
  else
    export AFL_BANDIT=0
  fi

  "$AFL_BIN" -i "$IN_DIR" -o "$run_dir" -- "$@" &
  local pid=$!

  wait_for_stats "$run_dir/fuzzer_stats" 120 1 || true
  local start_ts
  start_ts=$(date +%s)

  while kill -0 "$pid" 2>/dev/null; do
    sleep "$INTERVAL"
    local now_ts elapsed
    now_ts=$(date +%s)
    elapsed=$((now_ts - start_ts))
    collect_coverage_line "$mode" "$run_id" "$elapsed" \
      "$run_dir/fuzzer_stats" "$COVERAGE_CSV"
  done

  wait "$pid" || true

  local end_ts elapsed
  end_ts=$(date +%s)
  elapsed=$((end_ts - start_ts))
  collect_coverage_line "$mode" "$run_id" "$elapsed" \
    "$run_dir/fuzzer_stats" "$COVERAGE_CSV"

  local auc
  auc=$(calc_auc_from_coverage "$COVERAGE_CSV" "$mode" "$run_id")
  collect_stats_line "$mode" "$run_id" "$elapsed" \
    "$run_dir/fuzzer_stats" "$STATS_CSV" "$auc"
}

for seconds in "${DURATIONS[@]}"; do
  run_id=$(date +%Y%m%d%H%M%S)
  run_one "baseline" "$seconds" "$run_id" "$@"
  run_id=$(date +%Y%m%d%H%M%S)
  run_one "bandit" "$seconds" "$run_id" "$@"
  sleep 2
  unset AFL_EXIT_ON_TIME
  unset AFL_BANDIT_REWARD
  unset AFL_BANDIT_REWARD_FORMULA
  unset AFL_BANDIT_BETA
  unset AFL_BANDIT_GAMMA
  unset AFL_BANDIT_TEMPORAL
  unset AFL_BANDIT_LAMBDA
  unset AFL_BANDIT_GATE
  unset AFL_BANDIT_RHO
  unset AFL_BANDIT_ALPHA
  unset AFL_BANDIT
  unset AFL_EXIT_ON_TIME
  sleep 1
done
