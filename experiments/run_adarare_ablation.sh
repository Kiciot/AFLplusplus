#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'USAGE'
Usage: run_adarare_ablation.sh -i <in_dir> -o <out_root> [options] -- <target> [args...]

Options:
  -t <seconds>          Run duration per variant (default: 3600)
  --variant <name>      Run only one variant (default: all)
                        variants:
                          adarare_full
                          adarare_no_ctx
                          adarare_no_cmp
                          adarare_no_ips
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
MATRIX_CSV="$OUT_ROOT/adarare_ablation_matrix.csv"

mkdir -p "$OUT_ROOT"
write_header_once "$STATS_CSV" "$STATS_HEADER"
write_header_once "$COVERAGE_CSV" "$COVERAGE_HEADER"
write_header_once "$MATRIX_CSV" "variant,run_id,override_env,override_value,run_dir"

# Core AdaRare ablation variants.
# 1) adarare_full   : default behavior, no extra override
# 2) adarare_no_ctx : AFL_ADARARE_CONTEXTUAL=0
# 3) adarare_no_cmp : AFL_ADARARE_CMP_REWARD=0
# 4) adarare_no_ips : AFL_ADARARE_A6_OFFPOLICY_MODE=fixed
VARIANTS=(
  "adarare_full||"
  "adarare_no_ctx|AFL_ADARARE_CONTEXTUAL|0"
  "adarare_no_cmp|AFL_ADARARE_CMP_REWARD|0"
  "adarare_no_ips|AFL_ADARARE_A6_OFFPOLICY_MODE|fixed"
)

run_variant() {
  local variant_name=$1
  local override_env=$2
  local override_value=$3
  shift 3

  local run_id="${RUN_TAG}-${variant_name}"
  local run_dir="$OUT_ROOT/${variant_name}-${run_id}-${SECONDS}s"
  local default_dir="$run_dir/default"
  local stats_path="$default_dir/fuzzer_stats"
  mkdir -p "$run_dir"

  local -a env_args
  env_args=("AFL_BANDIT=1" "AFL_EXIT_ON_TIME=$SECONDS")
  if [[ -n "$override_env" ]]; then
    env_args+=("$override_env=$override_value")
  fi

  env "${env_args[@]}" \
    "$AFL_BIN" -i "$IN_DIR" -o "$run_dir" -- "$@" &
  local pid=$!

  wait_for_stats "$stats_path" 120 1 || true
  local start_ts
  start_ts=$(date +%s)

  while kill -0 "$pid" 2>/dev/null; do
    sleep "$INTERVAL"
    local now_ts elapsed
    now_ts=$(date +%s)
    elapsed=$((now_ts - start_ts))
    collect_coverage_line "$variant_name" "$run_id" "$elapsed" \
      "$stats_path" "$COVERAGE_CSV"
  done

  wait "$pid" || true

  local end_ts elapsed auc
  end_ts=$(date +%s)
  elapsed=$((end_ts - start_ts))

  collect_coverage_line "$variant_name" "$run_id" "$elapsed" \
    "$stats_path" "$COVERAGE_CSV"
  auc=$(calc_auc_from_coverage "$COVERAGE_CSV" "$variant_name" "$run_id")
  collect_stats_line "$variant_name" "$run_id" "$elapsed" \
    "$stats_path" "$STATS_CSV" "$auc"

  echo "$variant_name,$run_id,$override_env,$override_value,$run_dir" \
    >> "$MATRIX_CSV"
}

variant_found=0
for row in "${VARIANTS[@]}"; do
  IFS='|' read -r name override_env override_value <<<"$row"
  if [[ "$ONLY_VARIANT" != "all" && "$ONLY_VARIANT" != "$name" ]]; then
    continue
  fi
  variant_found=1
  run_variant "$name" "$override_env" "$override_value" "$@"
done

if [[ "$variant_found" -eq 0 ]]; then
  echo "Unknown variant: $ONLY_VARIANT" >&2
  usage
  exit 1
fi
