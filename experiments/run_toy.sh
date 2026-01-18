#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

AFL_CC=${AFL_CC:-$ROOT_DIR/afl-cc}
AFL_BIN=${AFL_BIN:-$ROOT_DIR/afl-fuzz}

TARGET_SRC="$SCRIPT_DIR/toy/target.c"
TARGET_BIN="$SCRIPT_DIR/toy/target"
IN_DIR="$SCRIPT_DIR/toy/inputs"
OUT_DIR="${OUT_DIR:-/tmp/afl-toy}"

"$AFL_CC" -O2 -g "$TARGET_SRC" -o "$TARGET_BIN"

: "${AFL_BANDIT:=1}"
: "${AFL_EXIT_ON_TIME:=60}"
export AFL_BANDIT
export AFL_EXIT_ON_TIME

mkdir -p "$OUT_DIR"
"$AFL_BIN" -i "$IN_DIR" -o "$OUT_DIR" -- "$TARGET_BIN" @@
