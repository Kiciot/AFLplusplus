#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'USAGE'
Usage: run_bandit.sh -i <in_dir> -o <out_root> -t <seconds> [-- <target> [args...]]

Environment:
  AFL_BIN           Path to afl-fuzz (default: repo_root/afl-fuzz)
  RUN_ID            Optional run id (default: timestamp)
  AFL_BANDIT_*      Bandit config variables passed through
USAGE
}

IN_DIR=""
OUT_ROOT=""
SECONDS=3600

while getopts ":i:o:t:h" opt; do
  case "$opt" in
    i) IN_DIR="$OPTARG" ;;
    o) OUT_ROOT="$OPTARG" ;;
    t) SECONDS="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

if [[ -z "$IN_DIR" || -z "$OUT_ROOT" || $# -lt 1 ]]; then
  usage
  exit 1
fi

RUN_ID=${RUN_ID:-$(date +%Y%m%d%H%M%S)}
MODE="bandit"
RUN_DIR="$OUT_ROOT/${MODE}-${RUN_ID}"
STATS_CSV="$OUT_ROOT/stats.csv"
COVERAGE_CSV="$OUT_ROOT/coverage.csv"

mkdir -p "$RUN_DIR"
write_header_once "$STATS_CSV" "$STATS_HEADER"
write_header_once "$COVERAGE_CSV" "$COVERAGE_HEADER"

AFL_BIN=${AFL_BIN:-$AFL_BIN_DEFAULT}

export AFL_EXIT_ON_TIME="$SECONDS"
: "${AFL_BANDIT:=1}"
export AFL_BANDIT

"$AFL_BIN" -i "$IN_DIR" -o "$RUN_DIR" -- "$@" &
PID=$!

wait_for_stats "$RUN_DIR/fuzzer_stats" 120 1 || true
wait "$PID" || true

collect_stats_line "$MODE" "$RUN_ID" "$SECONDS" "$RUN_DIR/fuzzer_stats" "$STATS_CSV" "0"
collect_coverage_line "$MODE" "$RUN_ID" "$SECONDS" "$RUN_DIR/fuzzer_stats" "$COVERAGE_CSV"
