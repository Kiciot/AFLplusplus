#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

AFL_BIN="$ROOT_DIR/afl-fuzz"
OUT_DIR="${OUT_DIR:-/tmp/afl-toy-asan}"
TARGET_SRC="$SCRIPT_DIR/toy/target.c"
TARGET_BIN="$SCRIPT_DIR/toy/target"
IN_DIR="$SCRIPT_DIR/toy/inputs"
AFL_CC=${AFL_CC:-$ROOT_DIR/afl-cc}

echo "[*] Building afl-fuzz with ASAN/UBSAN (NO_PYTHON=1, AFL_NO_LLVM=1)..."
pushd "$ROOT_DIR" >/dev/null
NO_PYTHON=1 AFL_NO_LLVM=1 AFL_USE_ASAN=1 AFL_USE_UBSAN=1 make clean all >/dev/null
popd >/dev/null

echo "[*] Building toy target with instrumentation..."
rm -f "$TARGET_BIN"
"$AFL_CC" -O2 -g -fsanitize=address,undefined "$TARGET_SRC" -o "$TARGET_BIN"

export AFL_EXIT_ON_TIME=${AFL_EXIT_ON_TIME:-60}
export AFL_BANDIT=${AFL_BANDIT:-1}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "[*] Running sanitizer smoke on toy for ${AFL_EXIT_ON_TIME}s..."
TIMEFORMAT='total %R sec'
time "$AFL_BIN" -i "$IN_DIR" -o "$OUT_DIR" -- "$TARGET_BIN" @@
