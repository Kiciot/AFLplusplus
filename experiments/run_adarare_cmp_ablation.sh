#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'USAGE'
Usage: run_adarare_cmp_ablation.sh -i <in_dir> -o <out_root> [options] -- <target> [args...]

Options:
  -t <seconds>          Run duration per variant (default: 3600)
  --variant <name>      Run only one variant (default: all)
                        variants:
                          adarare-base
                          adarare-cmp-byte
                          adarare-cmp-dist
                          adarare-cmp-dist-a3
                          adarare-cmp-full
  --interval <seconds>  Coverage sampling interval (default: 60)
  -h, --help            Show this help

Environment:
  AFL_BIN               Path to afl-fuzz (default: repo_root/afl-fuzz)
  RUN_TAG               Optional run tag prefix (default: timestamp)
USAGE
}

IN_DIR=""
OUT_ROOT=""
SECONDS=3600
INTERVAL=60
ONLY_VARIANT="all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IN_DIR="$2"; shift 2 ;;
    -o) OUT_ROOT="$2"; shift 2 ;;
    -t) SECONDS="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --variant) ONLY_VARIANT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$IN_DIR" || -z "$OUT_ROOT" || $# -lt 1 ]]; then
  usage
  exit 1
fi

AFL_BIN=${AFL_BIN:-$AFL_BIN_DEFAULT}
RUN_TAG=${RUN_TAG:-$(date +%Y%m%d%H%M%S)}

STATS_CSV="$OUT_ROOT/stats.csv"
COVERAGE_CSV="$OUT_ROOT/coverage.csv"
MATRIX_CSV="$OUT_ROOT/adarare_cmp_matrix.csv"

mkdir -p "$OUT_ROOT"
write_header_once "$STATS_CSV" "$STATS_HEADER"
write_header_once "$COVERAGE_CSV" "$COVERAGE_HEADER"
write_header_once "$MATRIX_CSV" "variant,run_id,cmp_reward,cmp_producer_mode,cmp_a3_boost,cmp_rarity_lambda,run_dir"

# Variant matrix for AdaRare CMPLOG-continuous-reward ablations.
# 1) adarare-base         : CMP_REWARD=0
# 2) adarare-cmp-byte     : reward on + byte producer only
# 3) adarare-cmp-dist     : reward on + distance producer/fallback
# 4) adarare-cmp-dist-a3  : dist mode + A3 cmp boost
# 5) adarare-cmp-full     : dist mode + A3 boost + rarity modulation
VARIANTS=(
  "adarare-base|0|2|0|0.0"
  "adarare-cmp-byte|1|1|0|0.0"
  "adarare-cmp-dist|1|2|0|0.0"
  "adarare-cmp-dist-a3|1|2|1|0.0"
  "adarare-cmp-full|1|2|1|0.25"
)

run_variant() {
  local variant_name=$1
  local cmp_reward=$2
  local cmp_mode=$3
  local cmp_a3_boost=$4
  local cmp_rarity_lambda=$5

  local run_id="${RUN_TAG}-${variant_name}"
  local run_dir="$OUT_ROOT/${variant_name}-${run_id}-${SECONDS}s"
  mkdir -p "$run_dir"

  env AFL_BANDIT=1 \
    AFL_EXIT_ON_TIME="$SECONDS" \
    AFL_ADARARE_CMP_REWARD="$cmp_reward" \
    AFL_ADARARE_CMP_PRODUCER_MODE="$cmp_mode" \
    AFL_ADARARE_CMP_A3_BOOST="$cmp_a3_boost" \
    AFL_ADARARE_CMP_RARITY_LAMBDA="$cmp_rarity_lambda" \
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
    collect_coverage_line "$variant_name" "$run_id" "$elapsed" \
      "$run_dir/fuzzer_stats" "$COVERAGE_CSV"
  done

  wait "$pid" || true

  local end_ts elapsed auc
  end_ts=$(date +%s)
  elapsed=$((end_ts - start_ts))

  collect_coverage_line "$variant_name" "$run_id" "$elapsed" \
    "$run_dir/fuzzer_stats" "$COVERAGE_CSV"
  auc=$(calc_auc_from_coverage "$COVERAGE_CSV" "$variant_name" "$run_id")
  collect_stats_line "$variant_name" "$run_id" "$elapsed" \
    "$run_dir/fuzzer_stats" "$STATS_CSV" "$auc"

  echo "$variant_name,$run_id,$cmp_reward,$cmp_mode,$cmp_a3_boost,$cmp_rarity_lambda,$run_dir" \
    >> "$MATRIX_CSV"
}

variant_found=0
for row in "${VARIANTS[@]}"; do
  IFS='|' read -r name cmp_reward cmp_mode cmp_a3_boost cmp_rarity_lambda <<<"$row"
  if [[ "$ONLY_VARIANT" != "all" && "$ONLY_VARIANT" != "$name" ]]; then
    continue
  fi
  variant_found=1
  run_variant "$name" "$cmp_reward" "$cmp_mode" "$cmp_a3_boost" "$cmp_rarity_lambda" "$@"
done

if [[ "$variant_found" -eq 0 ]]; then
  echo "Unknown variant: $ONLY_VARIANT" >&2
  usage
  exit 1
fi

