#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AFL_BIN_DEFAULT="$ROOT_DIR/afl-fuzz"

STATS_HEADER="mode,run_id,seconds,edges_found,execs_per_sec,total_execs,total_tmout,unique_crashes,unique_hangs,bandit_last_reward,bandit_last_rarity_mass,bandit_last_rarity_samples,bandit_last_gate,bandit_gate_samples,bandit_last_gate_execavg,bandit_gate_exec_samples,bandit_gate_min,bandit_exec_us_ema,bandit_dict_enable,bandit_dict_prob,bandit_extras_cnt,bandit_a_extras_cnt,bandit_last_havoc_ops,bandit_last_dict_ops,bandit_last_dict_ratio,bandit_discount,bandit_rarity_norm,bandit_last_path_len_avg,bandit_last_rarity_density,bandit_warmup_windows,bandit_in_warmup,bandit_cmplog_enabled,bandit_last_cmplog_execs,auc_edges"
COVERAGE_HEADER="mode,run_id,elapsed_s,edges_found,execs_per_sec,total_execs,total_tmout,unique_crashes"

stats_get() {
  local file=$1
  local key=$2
  if [[ ! -f "$file" ]]; then
    echo ""
    return
  fi
  awk -F':' -v k="$key" '{gsub(/[[:space:]]/,"",$1); if ($1==k) {gsub(/^[[:space:]]+/,"",$2); print $2; exit}}' "$file"
}

write_header_once() {
  local file=$1
  local header=$2
  if [[ ! -f "$file" ]]; then
    echo "$header" > "$file"
  fi
}

collect_stats_line() {
  local mode=$1
  local run_id=$2
  local seconds=$3
  local stats_file=$4
  local out_file=$5
  local auc_edges=${6:-0}

  local edges_found execs_per_sec total_execs total_tmout saved_crashes
  local saved_hangs last_reward last_gate gate_samples last_rarity_mass
  local last_rarity_samples last_gate_execavg gate_exec_samples gate_min exec_ema
  local dict_enable dict_prob bandit_extras_cnt bandit_a_extras_cnt
  local last_havoc_ops last_dict_ops last_dict_ratio
  local bandit_discount bandit_rarity_norm last_path_len_avg
  local last_rarity_density bandit_warmup_windows bandit_in_warmup
  local bandit_cmplog_enabled bandit_last_cmplog_execs

  edges_found=$(stats_get "$stats_file" "edges_found")
  execs_per_sec=$(stats_get "$stats_file" "execs_per_sec")
  total_execs=$(stats_get "$stats_file" "execs_done")
  total_tmout=$(stats_get "$stats_file" "total_tmout")
  saved_crashes=$(stats_get "$stats_file" "saved_crashes")
  saved_hangs=$(stats_get "$stats_file" "saved_hangs")
  last_reward=$(stats_get "$stats_file" "bandit_last_reward")
  last_rarity_mass=$(stats_get "$stats_file" "bandit_last_rarity_mass")
  last_rarity_samples=$(stats_get "$stats_file" "bandit_last_rarity_samples")
  last_gate=$(stats_get "$stats_file" "bandit_last_gate")
  gate_samples=$(stats_get "$stats_file" "bandit_gate_samples")
  last_gate_execavg=$(stats_get "$stats_file" "bandit_last_gate_execavg")
  gate_exec_samples=$(stats_get "$stats_file" "bandit_gate_exec_samples")
  gate_min=$(stats_get "$stats_file" "bandit_gate_min")
  exec_ema=$(stats_get "$stats_file" "bandit_exec_us_ema")
  dict_enable=$(stats_get "$stats_file" "bandit_dict_enable")
  dict_prob=$(stats_get "$stats_file" "bandit_dict_prob")
  bandit_extras_cnt=$(stats_get "$stats_file" "bandit_extras_cnt")
  bandit_a_extras_cnt=$(stats_get "$stats_file" "bandit_a_extras_cnt")
  last_havoc_ops=$(stats_get "$stats_file" "bandit_last_havoc_ops")
  last_dict_ops=$(stats_get "$stats_file" "bandit_last_dict_ops")
  last_dict_ratio=$(stats_get "$stats_file" "bandit_last_dict_ratio")
  bandit_discount=$(stats_get "$stats_file" "bandit_discount")
  bandit_rarity_norm=$(stats_get "$stats_file" "bandit_rarity_norm")
  last_path_len_avg=$(stats_get "$stats_file" "bandit_last_path_len_avg")
  last_rarity_density=$(stats_get "$stats_file" "bandit_last_rarity_density")
  bandit_warmup_windows=$(stats_get "$stats_file" "bandit_warmup_windows")
  bandit_in_warmup=$(stats_get "$stats_file" "bandit_in_warmup")
  bandit_cmplog_enabled=$(stats_get "$stats_file" "bandit_cmplog_enabled")
  bandit_last_cmplog_execs=$(stats_get "$stats_file" "bandit_last_cmplog_execs")

  echo "$mode,$run_id,$seconds,$edges_found,$execs_per_sec,$total_execs,$total_tmout,$saved_crashes,$saved_hangs,$last_reward,$last_rarity_mass,$last_rarity_samples,$last_gate,$gate_samples,$last_gate_execavg,$gate_exec_samples,$gate_min,$exec_ema,$dict_enable,$dict_prob,$bandit_extras_cnt,$bandit_a_extras_cnt,$last_havoc_ops,$last_dict_ops,$last_dict_ratio,$bandit_discount,$bandit_rarity_norm,$last_path_len_avg,$last_rarity_density,$bandit_warmup_windows,$bandit_in_warmup,$bandit_cmplog_enabled,$bandit_last_cmplog_execs,$auc_edges" >> "$out_file"
}

collect_coverage_line() {
  local mode=$1
  local run_id=$2
  local elapsed_s=$3
  local stats_file=$4
  local out_file=$5

  local edges_found execs_per_sec total_execs total_tmout saved_crashes
  edges_found=$(stats_get "$stats_file" "edges_found")
  execs_per_sec=$(stats_get "$stats_file" "execs_per_sec")
  total_execs=$(stats_get "$stats_file" "execs_done")
  total_tmout=$(stats_get "$stats_file" "total_tmout")
  saved_crashes=$(stats_get "$stats_file" "saved_crashes")

  echo "$mode,$run_id,$elapsed_s,$edges_found,$execs_per_sec,$total_execs,$total_tmout,$saved_crashes" >> "$out_file"
}

wait_for_stats() {
  local stats_file=$1
  local retries=${2:-60}
  local sleep_s=${3:-1}
  local i=0
  while [[ $i -lt $retries ]]; do
    if [[ -f "$stats_file" ]]; then
      return 0
    fi
    sleep "$sleep_s"
    i=$((i+1))
  done
  return 1
}

calc_auc_from_coverage() {
  local coverage_csv=$1
  local mode=$2
  local run_id=$3

  awk -F',' -v mode="$mode" -v run_id="$run_id" 'NR==1 {next} $1==mode && $2==run_id {t=$3+0; c=$4+0; if (n>0) {auc+= (t-prev_t) * (c+prev_c)/2} prev_t=t; prev_c=c; n++} END {print (n>1)?auc:0}' "$coverage_csv"
}
