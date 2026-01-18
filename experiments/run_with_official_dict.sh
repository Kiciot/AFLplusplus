#!/usr/bin/env bash
# Usage: AFL_NO_SEEDS=1 ./experiments/run_with_official_dict.sh -- <target cmd...>
set -euo pipefail

ROOT="${ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)}"
OUT="${OUT:-/tmp/afl_official_dict_$(date +%Y%m%d_%H%M%S)}"
DICT_DIR="$ROOT/dictionaries"

if [[ $# -lt 1 || $1 != "--" ]]; then
  echo "Usage: [ROOT=<path>] [OUT=<outdir>] [AFL_NO_SEEDS=1] [AFL_NO_DICT=1] [AFL_DICT=<dict>] ./experiments/run_with_official_dict.sh -- <target cmd...>" >&2
  exit 1
fi
shift

# Infer kind from env or target name
kind="${TARGET_KIND:-}"
if [[ -z "$kind" && $# -gt 0 ]]; then
  base=$(basename "$1")
  case "$base" in
    *xml*) kind="xml" ;;
    *json*) kind="json" ;;
    *sql*) kind="sql" ;;
    *png*) kind="png" ;;
    *zip*) kind="zip" ;;
    *elf*) kind="elf" ;;
  esac
fi

dict="${AFL_DICT:-}"
if [[ -z "$dict" ]]; then
  case "$kind" in
    xml)  dict="$DICT_DIR/xml.dict" ;;
    json) dict="$DICT_DIR/json.dict" ;;
    sql)  dict="$DICT_DIR/sql.dict" ;;
    png)  dict="$DICT_DIR/png.dict" ;;
    zip)  dict="$DICT_DIR/zip.dict" ;;
    elf)  dict="$DICT_DIR/elf.dict" ;;
  esac
fi

if [[ -z "$dict" || ! -f "$dict" ]]; then
  fallback="/tmp/aflpp_default.dict"
  : >"$fallback"
  for candidate in xml json sql html common; do
    cpath="$DICT_DIR/$candidate.dict"
    [[ -f "$cpath" ]] && cat "$cpath" >>"$fallback"
  done
  dict="$fallback"
fi

# Input seeds
if [[ "${AFL_NO_SEEDS:-0}" == "1" || -z "${IN_DIR:-}" ]]; then
  IN_DIR="/tmp/afl_min_seed_$(date +%s)"
  mkdir -p "$IN_DIR"
  printf '\x00' >"$IN_DIR/seed"
else
  IN_DIR="${IN_DIR}"
fi

mkdir -p "$OUT"

cmd=( "$ROOT/afl-fuzz" -i "$IN_DIR" -o "$OUT" )
if [[ "${AFL_NO_DICT:-0}" != "1" ]]; then
  cmd+=( -x "$dict" )
fi
cmd+=( -- "$@" )

echo "afl-fuzz input : $IN_DIR"
echo "afl-fuzz dict  : $dict"
echo "afl-fuzz out   : $OUT"

exec "${cmd[@]}"
