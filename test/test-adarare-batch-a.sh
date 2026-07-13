#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ ! -x ./afl-fuzz ] || [ ! -x ./afl-cc ]; then
  echo "[-] Build AFL++ before running this test." >&2
  exit 1
fi

unset AFL_ADARARE_POLICY AFL_ADARARE_ENABLE_A6 AFL_ADARARE_CONTEXT_MODE
unset AFL_ADARARE_STATIC_ARM AFL_BANDIT_WINDOW_MS AFL_ADARARE_CONTEXTUAL

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/adarare-batch-a-policy.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
mkdir -p "$WORK_DIR/in"
cp test-instr.c "$WORK_DIR/in/seed"
./afl-cc test-instr.c -o "$WORK_DIR/target" >/dev/null 2>&1

run_valid() {
  name=$1
  shift
  mkdir -p "$WORK_DIR/$name"
  if ! env \
      AFL_NO_UI=1 \
      AFL_SKIP_CPUFREQ=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      AFL_BANDIT=1 \
      "$@" \
      ./afl-fuzz -M main -i "$WORK_DIR/in" -o "$WORK_DIR/$name/out" \
        -V 2 -- "$WORK_DIR/target" >"$WORK_DIR/$name.log" 2>&1; then
    echo "[-] Valid configuration failed: $name" >&2
    sed -n '1,220p' "$WORK_DIR/$name.log" >&2
    return 1
  fi
}

expect_fail() {
  name=$1
  shift
  mkdir -p "$WORK_DIR/$name"
  if env \
      AFL_NO_UI=1 \
      AFL_SKIP_CPUFREQ=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      AFL_BANDIT=1 \
      "$@" \
      ./afl-fuzz -M main -i "$WORK_DIR/in" -o "$WORK_DIR/$name/out" \
        -V 1 -- "$WORK_DIR/target" >"$WORK_DIR/$name.log" 2>&1; then
    echo "[-] Invalid configuration unexpectedly succeeded: $name" >&2
    exit 1
  fi
  grep -q 'PROGRAM ABORT' "$WORK_DIR/$name.log"
}

run_valid default_full
run_valid full_fast \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=linucb \
  AFL_ADARARE_ENABLE_A6=1 AFL_ADARARE_CONTEXT_MODE=dynamic
run_valid linucb_no_a6 \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=linucb \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=dynamic
run_valid constant_context_no_a6 \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=linucb \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=constant
run_valid random_profile \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=random_profile \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=dynamic
run_valid round_robin_profile \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=round_robin_profile \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=dynamic
run_valid static_a1 \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=static_profile \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=dynamic \
  AFL_ADARARE_STATIC_ARM=1
run_valid static_a5 \
  AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_POLICY=static_profile \
  AFL_ADARARE_ENABLE_A6=0 AFL_ADARARE_CONTEXT_MODE=dynamic \
  AFL_ADARARE_STATIC_ARM=5

expect_fail unknown_policy AFL_ADARARE_POLICY=not_a_policy
expect_fail unknown_context AFL_ADARARE_CONTEXT_MODE=not_a_context
expect_fail invalid_enable_a6 AFL_ADARARE_ENABLE_A6=2
expect_fail static_missing_arm \
  AFL_ADARARE_POLICY=static_profile AFL_ADARARE_ENABLE_A6=0
expect_fail static_bad_arm \
  AFL_ADARARE_POLICY=static_profile AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_STATIC_ARM=6
expect_fail random_with_a6 \
  AFL_ADARARE_POLICY=random_profile AFL_ADARARE_ENABLE_A6=1
expect_fail round_robin_with_a6 \
  AFL_ADARARE_POLICY=round_robin_profile AFL_ADARARE_ENABLE_A6=1
expect_fail static_with_a6 \
  AFL_ADARARE_POLICY=static_profile AFL_ADARARE_ENABLE_A6=1 \
  AFL_ADARARE_STATIC_ARM=1

python3 - "$WORK_DIR" <<'PY'
import csv
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def load(name):
    out = root / name / "out" / "main"
    config = json.loads((out / ".adarare_config.json").read_text())
    bandit_path = out / ".adarare_bandit.csv"
    overhead_path = out / ".adarare_overhead.csv"
    rows = list(csv.DictReader(bandit_path.open())) if bandit_path.exists() else []
    overhead = list(csv.DictReader(overhead_path.open())) if overhead_path.exists() else []
    return config, rows, overhead

default, default_rows, default_overhead = load("default_full")
assert default["policy"] == "linucb"
assert default["enable_a6"] == 1
assert default["context_mode"] == "dynamic"
assert default["window_ms"] == 5000
assert default["static_arm"] is None

reward_defaults = {
    "reward_alpha": 0.75,
    "reward_beta": 0.20,
    "reward_gamma": 0.05,
    "reward_delta": 0.35,
}
for key, value in reward_defaults.items():
    assert default[key] == value, (key, default[key], value)

full_fast, full_rows, full_overhead = load("full_fast")
assert full_fast["policy"] == "linucb"
assert full_fast["enable_a6"] == 1
assert full_fast["context_mode"] == "dynamic"
assert full_rows and full_overhead
assert all(0 <= int(row["arm_id"]) <= 5 for row in full_rows)
assert all(0 <= int(row["effective_arm"]) <= 4 for row in full_rows)
assert any(int(row["arm_id"]) == 5 for row in full_rows), [
    row["arm_id"] for row in full_rows
]

expected = {
    "linucb_no_a6": ("linucb", "dynamic", None),
    "constant_context_no_a6": ("linucb", "constant", None),
    "random_profile": ("random_profile", "dynamic", None),
    "round_robin_profile": ("round_robin_profile", "dynamic", None),
    "static_a1": ("static_profile", "dynamic", 1),
    "static_a5": ("static_profile", "dynamic", 5),
}

loaded = {}
required_bandit = {
    "arm_id", "effective_arm", "cur_window_ms",
    "policy", "enable_a6", "context_mode", "static_arm",
    "raw_x0", "raw_x1", "raw_x2", "raw_x3", "raw_x4", "raw_x5",
    "x0", "x1", "x2", "x3", "x4", "x5",
}
required_overhead = {
    "selected_arm", "effective_arm", "cur_window_ms", "policy",
    "enable_a6", "context_mode", "static_arm",
}

for name, (policy, context_mode, static_arm) in expected.items():
    config, rows, overhead = load(name)
    loaded[name] = (config, rows, overhead)
    assert config["policy"] == policy
    assert config["enable_a6"] == 0
    assert config["context_mode"] == context_mode
    assert config["static_arm"] == static_arm
    assert config["window_ms"] == 25
    for key, value in reward_defaults.items():
        assert config[key] == value, (name, key, config[key], value)
    assert rows, f"no bandit telemetry for {name}"
    assert overhead, f"no overhead telemetry for {name}"
    assert required_bandit <= set(rows[0]), (name, required_bandit - set(rows[0]))
    assert required_overhead <= set(overhead[0]), (name, required_overhead - set(overhead[0]))
    for row in rows:
        assert row["policy"] == policy
        assert row["enable_a6"] == "0"
        assert row["context_mode"] == context_mode
        assert 0 <= int(row["arm_id"]) <= 4
        assert 0 <= int(row["effective_arm"]) <= 4

constant_rows = loaded["constant_context_no_a6"][1]
for row in constant_rows:
    raw = [float(row[f"raw_x{i}"]) for i in range(6)]
    smooth = [float(row[f"x{i}"]) for i in range(6)]
    assert raw == [1.0, 0.0, 0.0, 0.0, 0.0, 0.0], raw
    assert smooth == [1.0, 0.0, 0.0, 0.0, 0.0, 0.0], smooth

rr = [int(row["arm_id"]) for row in loaded["round_robin_profile"][1]]
assert len(rr) >= 6, rr
assert rr[:6] == [0, 1, 2, 3, 4, 0], rr[:6]

for row in loaded["static_a1"][1]:
    assert int(row["arm_id"]) == int(row["effective_arm"]) == 0
    assert row["static_arm"] == "1"
for row in loaded["static_a5"][1]:
    assert int(row["arm_id"]) == int(row["effective_arm"]) == 4
    assert row["static_arm"] == "5"

print("[+] AdaRare Batch A policy/config test passed")
PY

grep -Fq 'double A[6][6]' include/afl-fuzz-bandit.h
grep -Fq 'double b[6]' include/afl-fuzz-bandit.h

echo "[+] Defaults, no-A6 arm range, constant context, static arms, round-robin, telemetry, reward defaults, and fail-fast checks passed."
