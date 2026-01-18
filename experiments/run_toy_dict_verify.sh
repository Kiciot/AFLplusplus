#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT_DIR="/tmp/bandit_dict_verif_$(date +%Y%m%d_%H%M%S)"
TARGET_SRC="$ROOT_DIR/experiments/toy/target.c"
TARGET_BIN="$ROOT_DIR/experiments/toy/target"
DICT_FILE="$ROOT_DIR/experiments/toy/dict.txt"
STATS_FILE="$OUT_DIR/default/fuzzer_stats"

mkdir -p "$ROOT_DIR/experiments/toy"

# Build toy target with instrumentation
"$ROOT_DIR/afl-cc" -O2 -g "$TARGET_SRC" -o "$TARGET_BIN"

# Prepare a small dictionary
cat >"$DICT_FILE" <<'EOF'
"test"
"data"
"AAAA"
"1234"
"function"
EOF

mkdir -p "$OUT_DIR"

export AFL_BANDIT=1
export AFL_BANDIT_DICT=1
export AFL_BANDIT_WINDOW_MS=1000
export AFL_BANDIT_REWARD=rarity_mass
export AFL_BANDIT_RARITY_NORM=path_len
export AFL_BANDIT_DISCOUNT=0.97
export AFL_BANDIT_WARMUP_WINDOWS=5
export AFL_NO_UI=1
export AFL_EXIT_ON_TIME=60

"$ROOT_DIR/afl-fuzz" -i "$ROOT_DIR/experiments/toy/inputs" \
  -o "$OUT_DIR" -x "$DICT_FILE" -- "$TARGET_BIN" @@

if [[ ! -f "$STATS_FILE" ]]; then
  echo "ERROR: fuzzer_stats not found at $STATS_FILE" >&2
  exit 1
fi

stat_get() {
  local key=$1
  awk -F':' -v k="$key" '
    {gsub(/^[[:space:]]+/,"",$1);}
    $1==k {gsub(/^[[:space:]]+/,"",$2); gsub(/[[:space:]]+$/,"",$2); print $2; exit}
  ' "$STATS_FILE"
}

dict_prob=$(stat_get "bandit_dict_prob"); dict_prob=${dict_prob:-0}
hops=$(stat_get "bandit_last_havoc_ops"); hops=${hops:-0}
dops=$(stat_get "bandit_last_dict_ops"); dops=${dops:-0}
dratio=$(stat_get "bandit_last_dict_ratio"); dratio=${dratio:-0}
extras_cnt=$(stat_get "bandit_extras_cnt"); extras_cnt=${extras_cnt:-0}
a_extras_cnt=$(stat_get "bandit_a_extras_cnt"); a_extras_cnt=${a_extras_cnt:-0}

echo "==== Path1 dict verification ===="
echo "out_dir             : $OUT_DIR"
echo "bandit_dict_prob    : $dict_prob"
echo "bandit_last_havoc_ops: $hops"
echo "bandit_last_dict_ops : $dops"
echo "bandit_last_dict_ratio: $dratio"
echo "bandit_extras_cnt   : $extras_cnt"
echo "bandit_a_extras_cnt : $a_extras_cnt"

if [[ ${dict_prob%.*} -gt 0 && ${extras_cnt%.*} -gt 0 && ${dops%.*} -eq 0 ]]; then
  echo "ERROR: dict_prob>0 and extras present but no dict ops recorded" >&2
  exit 1
fi

exit 0
