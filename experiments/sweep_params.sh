#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'USAGE'
Usage: sweep_params.sh -i <in_dir> -o <out_root> [options] -- <target> [args...]

Options:
  --lambda-list "0 0.0005 0.001"
  --rho-list "0.5 1.0 2.0"        (exec_us gate)
  --alpha-list "0.25 0.5 1.0"     (path_len gate)
  --gate exec_us|path_len|none
  --t1 <seconds>                  (default 3600)
  --t2 <seconds>                  (default 14400)
  --temporal 0|1                  (default 1)

Environment:
  AFL_BIN     Path to afl-fuzz (default: repo_root/afl-fuzz)
USAGE
}

IN_DIR=""
OUT_ROOT=""
LAMBDA_LIST="0 0.0005 0.001"
RHO_LIST="0.5 1.0 2.0"
ALPHA_LIST="0.25 0.5 1.0"
GATE="exec_us"
T1=3600
T2=14400
TEMPORAL=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IN_DIR="$2"; shift 2 ;;
    -o) OUT_ROOT="$2"; shift 2 ;;
    --lambda-list) LAMBDA_LIST="$2"; shift 2 ;;
    --rho-list) RHO_LIST="$2"; shift 2 ;;
    --alpha-list) ALPHA_LIST="$2"; shift 2 ;;
    --gate) GATE="$2"; shift 2 ;;
    --t1) T1="$2"; shift 2 ;;
    --t2) T2="$2"; shift 2 ;;
    --temporal) TEMPORAL="$2"; shift 2 ;;
    -h) usage; exit 0 ;;
    --) shift; break ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$IN_DIR" || -z "$OUT_ROOT" || $# -lt 1 ]]; then
  usage
  exit 1
fi

AFL_BIN=${AFL_BIN:-$AFL_BIN_DEFAULT}
RESULTS_CSV="$OUT_ROOT/results.csv"

mkdir -p "$OUT_ROOT"
if [[ ! -f "$RESULTS_CSV" ]]; then
  echo "run_id,lambda,temporal,gate,rho,alpha,coverage_1h,coverage_4h,execs_per_sec,total_tmout,unique_crashes,unique_hangs" > "$RESULTS_CSV"
fi

run_sweep() {
  local lambda=$1
  local rho=$2
  local alpha=$3

  local run_id
  run_id=$(date +%Y%m%d%H%M%S)
  local run_dir="$OUT_ROOT/sweep-${run_id}-lam${lambda}-rho${rho}-alpha${alpha}"
  mkdir -p "$run_dir"

  export AFL_BANDIT=1
  export AFL_BANDIT_TEMPORAL="$TEMPORAL"
  export AFL_BANDIT_LAMBDA="$lambda"
  export AFL_BANDIT_GATE="$GATE"
  export AFL_BANDIT_RHO="$rho"
  export AFL_BANDIT_ALPHA="$alpha"
  export AFL_EXIT_ON_TIME="$T2"

  "$AFL_BIN" -i "$IN_DIR" -o "$run_dir" -- "$@" &
  local pid=$!

  wait_for_stats "$run_dir/fuzzer_stats" 120 1 || true

  local start_ts
  start_ts=$(date +%s)

  local cov_1h=""
  if kill -0 "$pid" 2>/dev/null; then
    local remaining=$T1
    while [[ $remaining -gt 0 ]] && kill -0 "$pid" 2>/dev/null; do
      local step=10
      if [[ $remaining -lt $step ]]; then
        step=$remaining
      fi
      sleep "$step" || true
      remaining=$((remaining - step))
    done
    if [[ -f "$run_dir/fuzzer_stats" ]]; then
      cov_1h=$(stats_get "$run_dir/fuzzer_stats" "edges_found")
    fi
  fi

  wait "$pid" || true

  local cov_4h execs_per_sec total_tmout saved_crashes saved_hangs
  cov_4h=$(stats_get "$run_dir/fuzzer_stats" "edges_found")
  execs_per_sec=$(stats_get "$run_dir/fuzzer_stats" "execs_per_sec")
  total_tmout=$(stats_get "$run_dir/fuzzer_stats" "total_tmout")
  saved_crashes=$(stats_get "$run_dir/fuzzer_stats" "saved_crashes")
  saved_hangs=$(stats_get "$run_dir/fuzzer_stats" "saved_hangs")

  echo "$run_id,$lambda,$TEMPORAL,$GATE,$rho,$alpha,$cov_1h,$cov_4h,$execs_per_sec,$total_tmout,$saved_crashes,$saved_hangs" >> "$RESULTS_CSV"
}

if [[ "$GATE" == "path_len" ]]; then
  for lambda in $LAMBDA_LIST; do
    for alpha in $ALPHA_LIST; do
      run_sweep "$lambda" "0" "$alpha" "$@"
    done
  done
else
  for lambda in $LAMBDA_LIST; do
    for rho in $RHO_LIST; do
      run_sweep "$lambda" "$rho" "0" "$@"
    done
  done
fi
