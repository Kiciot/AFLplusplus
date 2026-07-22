#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ ! -x ./afl-fuzz ]; then
  echo "[-] Build afl-fuzz before running this test." >&2
  exit 1
fi

unset AFL_ADARARE_MODE AFL_ADARARE_ENABLE_A6
unset AFL_ADARARE_RARITY_CONTEXT AFL_ADARARE_RARITY_REWARD
unset AFL_ADARARE_RARITY_GATE AFL_ADARARE_TELEMETRY AFL_ADARARE_AUDIT
unset AFL_ADARARE_POLICY AFL_ADARARE_CONTEXT_MODE AFL_ADARARE_STATIC_ARM
unset AFL_BANDIT AFL_BANDIT_WINDOW_MS AFL_CMPLOG AFL_LLVM_CMPLOG AFL_GCC_CMPLOG

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/adarare-batch-b-runtime.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
mkdir -p "$WORK_DIR/in"
cp test-instr.c "$WORK_DIR/in/seed"
FUZZ_ROLE_ARGS="-M main"
cc -DUSEMMAP=1 -Iinclude -c instrumentation/afl-compiler-rt.o.c \
  -o "$WORK_DIR/afl-compiler-rt.o" >/dev/null 2>&1
cc -fsanitize-coverage=trace-pc-guard,trace-cmp test-instr.c \
  "$WORK_DIR/afl-compiler-rt.o" -o "$WORK_DIR/target" >/dev/null 2>&1
cc -fsanitize-coverage=trace-pc-guard,trace-cmp test-instr.c \
  "$WORK_DIR/afl-compiler-rt.o" -o "$WORK_DIR/cmplog-target" \
  >/dev/null 2>&1

run_case() {
  name=$1
  cmplog=$2
  shift 2
  mkdir -p "$WORK_DIR/$name"
  if [ "$cmplog" = yes ]; then
    if env AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_MAP_SIZE=65536 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "$@" \
      ./afl-fuzz $FUZZ_ROLE_ARGS -i "$WORK_DIR/in" \
      -o "$WORK_DIR/$name/out" \
      -V 2 -c "$WORK_DIR/cmplog-target" -- "$WORK_DIR/target" \
      >"$WORK_DIR/$name.log" 2>&1; then :; else
      echo "[-] Smoke case failed: $name" >&2
      sed -n '1,220p' "$WORK_DIR/$name.log" >&2
      exit 1
    fi
  else
    if env AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_MAP_SIZE=65536 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "$@" \
      ./afl-fuzz $FUZZ_ROLE_ARGS -i "$WORK_DIR/in" \
      -o "$WORK_DIR/$name/out" \
      -V 2 -- "$WORK_DIR/target" >"$WORK_DIR/$name.log" 2>&1; then :; else
      echo "[-] Smoke case failed: $name" >&2
      sed -n '1,220p' "$WORK_DIR/$name.log" >&2
      exit 1
    fi
  fi
}

expect_fail() {
  name=$1
  expected=$2
  shift 2
  mkdir -p "$WORK_DIR/$name"
  if env AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_MAP_SIZE=65536 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "$@" \
      ./afl-fuzz $FUZZ_ROLE_ARGS -i "$WORK_DIR/in" \
      -o "$WORK_DIR/$name/out" \
      -V 1 -- "$WORK_DIR/target" >"$WORK_DIR/$name.log" 2>&1; then
    echo "[-] Invalid configuration unexpectedly succeeded: $name" >&2
    exit 1
  fi
  grep -Fq "$expected" "$WORK_DIR/$name.log"
}

run_case batchb_aflpp_default no \
  AFL_BANDIT=0 AFL_ADARARE_MODE=off AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_RARITY_CONTEXT=0 AFL_ADARARE_RARITY_REWARD=0 \
  AFL_ADARARE_RARITY_GATE=0 AFL_ADARARE_TELEMETRY=0 AFL_ADARARE_AUDIT=1
run_case batchb_aflpp_cmplog_matched yes \
  AFL_BANDIT=0 AFL_ADARARE_MODE=off AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_RARITY_CONTEXT=0 AFL_ADARARE_RARITY_REWARD=0 \
  AFL_ADARARE_RARITY_GATE=0 AFL_ADARARE_TELEMETRY=0 AFL_ADARARE_AUDIT=1
run_case batchb_aflpp_shadow yes \
  AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_MODE=shadow \
  AFL_ADARARE_POLICY=linucb AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_RARITY_CONTEXT=1 AFL_ADARARE_RARITY_REWARD=1 \
  AFL_ADARARE_RARITY_GATE=1 AFL_ADARARE_TELEMETRY=1 AFL_ADARARE_AUDIT=1
run_case batchb_adarare_full yes \
  AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_MODE=active \
  AFL_ADARARE_POLICY=linucb AFL_ADARARE_ENABLE_A6=1 \
  AFL_ADARARE_RARITY_CONTEXT=1 AFL_ADARARE_RARITY_REWARD=1 \
  AFL_ADARARE_RARITY_GATE=1 AFL_ADARARE_TELEMETRY=1 AFL_ADARARE_AUDIT=1
run_case batchb_adarare_no_a6 yes \
  AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_MODE=active \
  AFL_ADARARE_POLICY=linucb AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_RARITY_CONTEXT=1 AFL_ADARARE_RARITY_REWARD=1 \
  AFL_ADARARE_RARITY_GATE=1 AFL_ADARARE_TELEMETRY=1 AFL_ADARARE_AUDIT=1
run_case batchb_adarare_no_rarity yes \
  AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 AFL_ADARARE_MODE=active \
  AFL_ADARARE_POLICY=linucb AFL_ADARARE_ENABLE_A6=0 \
  AFL_ADARARE_RARITY_CONTEXT=0 AFL_ADARARE_RARITY_REWARD=0 \
  AFL_ADARARE_RARITY_GATE=0 AFL_ADARARE_TELEMETRY=1 AFL_ADARARE_AUDIT=1
run_case legacy_full_default no AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25
run_case legacy_empty_values no AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 \
  AFL_ADARARE_ENABLE_A6= AFL_ADARARE_CONTEXT_MODE=
run_case legacy_rarity_reward no AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=25 \
  AFL_BANDIT_REWARD=rarity_mass

expect_fail invalid_mode 'Invalid AFL_ADARARE_MODE=' \
  AFL_BANDIT=0 AFL_ADARARE_MODE=invalid
expect_fail off_a6_conflict 'AFL_ADARARE_MODE=off requires' \
  AFL_BANDIT=0 AFL_ADARARE_MODE=off AFL_ADARARE_ENABLE_A6=1
expect_fail shadow_policy_conflict 'AFL_ADARARE_MODE=shadow requires' \
  AFL_BANDIT=1 AFL_ADARARE_MODE=shadow AFL_ADARARE_POLICY=random_profile \
  AFL_ADARARE_ENABLE_A6=0
expect_fail invalid_rarity_bool 'Invalid AFL_ADARARE_RARITY_GATE=' \
  AFL_BANDIT=0 AFL_ADARARE_MODE=off AFL_ADARARE_RARITY_GATE=2
expect_fail off_enabled_bandit 'AFL_ADARARE_MODE=off conflicts' \
  AFL_BANDIT=1 AFL_ADARARE_MODE=off
expect_fail active_disabled_bandit 'conflicts with AFL_BANDIT=0' \
  AFL_BANDIT=0 AFL_ADARARE_MODE=active
expect_fail shadow_telemetry_off 'AFL_ADARARE_MODE=shadow requires AFL_ADARARE_TELEMETRY=1' \
  AFL_BANDIT=1 AFL_ADARARE_MODE=shadow AFL_ADARARE_TELEMETRY=0
expect_fail shadow_context_conflict 'AFL_ADARARE_MODE=shadow requires AFL_ADARARE_CONTEXT_MODE=dynamic' \
  AFL_BANDIT=1 AFL_ADARARE_MODE=shadow AFL_ADARARE_CONTEXT_MODE=constant

python3 - "$WORK_DIR" <<'PY'
import csv
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
checks = 0

def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)

def load(name):
    out = root / name / "out"
    if (out / "main").is_dir():
        out = out / "main"
    evidence_path = out / ".adarare_runtime_evidence.json"
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else None
    config = json.loads((out / ".adarare_config.json").read_text())
    bandit_path = out / ".adarare_bandit.csv"
    rows = list(csv.DictReader(bandit_path.open())) if bandit_path.exists() else []
    return out, evidence, config, rows

off_out, off, off_cfg, off_rows = load("batchb_aflpp_default")
matched_out, matched, matched_cfg, matched_rows = load("batchb_aflpp_cmplog_matched")
shadow_out, shadow, shadow_cfg, shadow_rows = load("batchb_aflpp_shadow")
full_out, full, full_cfg, full_rows = load("batchb_adarare_full")
no_a6_out, no_a6, no_a6_cfg, no_a6_rows = load("batchb_adarare_no_a6")
no_rarity_out, no_rarity, no_rarity_cfg, no_rarity_rows = load(
    "batchb_adarare_no_rarity"
)
legacy_out, legacy, legacy_cfg, legacy_rows = load("legacy_full_default")
legacy_empty_out, legacy_empty, legacy_empty_cfg, legacy_empty_rows = load(
    "legacy_empty_values"
)
legacy_rarity_out, legacy_rarity, legacy_rarity_cfg, legacy_rarity_rows = load(
    "legacy_rarity_reward"
)

check(not off["controller_enabled"] and off["mode"] == "off",
      "off constructed a controller")
check(off["candidate_action_count"] == 0 and off["applied_action_count"] == 0,
      "off selected or applied an action")
check(off["profile_knobs"]["adarare_dict_prob"] == 20 and
      off["profile_knobs"]["adarare_havoc_mul_pct"] == 100 and
      off["profile_knobs"]["adarare_prefer_favored"] == 0 and
      off["profile_knobs"]["adarare_prefer_new"] == 0 and
      off["profile_knobs"]["bandit_dict_enable"] == 1,
      f"off changed a profile knob: {off['profile_knobs']}")
check(not (off_out / ".adarare_bandit.csv").exists(),
      "off wrote periodic controller telemetry")
check(shadow["candidate_action_count"] > 0 and shadow["mode"] == "shadow",
      "shadow did not compute a candidate")
check(shadow_cfg["policy"] == "linucb" and
      shadow_cfg["context_mode"] == "dynamic" and shadow_rows and
      all(row["mode"] == "shadow" for row in shadow_rows),
      "shadow did not use the dynamic LinUCB telemetry path")
check(shadow["applied_action_count"] == 0 and shadow["last_action_applied"] is False,
      "shadow applied a candidate")
check(shadow_rows and
      all(int(row["action_applied"]) == 0 and
          0 <= int(row["candidate_arm"]) < 6 for row in shadow_rows),
      "shadow telemetry recorded an applied action")
check(shadow["profile_knobs"]["adarare_havoc_mul_pct"] == 100 and
      shadow["profile_knobs"]["adarare_prefer_favored"] == 0 and
      shadow["profile_knobs"]["adarare_prefer_new"] == 0 and
      shadow["profile_knobs"]["adarare_dict_prob"] == 20 and
      shadow["profile_knobs"]["bandit_dict_enable"] == 1,
      "shadow changed a profile knob")
check(full["applied_action_count"] > 0 and full["mode"] == "active",
      "active did not apply an action")
check(sum(no_a6["candidate_arm_counts"][5:]) == 0 and
      sum(no_a6["applied_arm_counts"][5:]) == 0,
      "A6 was selected or applied with A6 disabled")
check(full["enable_a6"] == 1 and len(full["candidate_arm_counts"]) == 6,
      "Full configuration did not allow A6")
check(no_rarity_cfg["num_arms"] == 6 and
      no_rarity["rarity_context"] == 0 and
      all(float(row["raw_x1"]) == 0.0 and float(row["x1"]) == 0.0
          for row in no_rarity_rows),
      "no-rarity context or model dimension was not stable")
check(no_rarity["rarity_reward"] == 0 and
      all(float(row["rarity_term"]) == 0.0 and
          float(row["delta_rarity"]) == 0.0
          for row in no_rarity_rows),
      "no-rarity reward contribution was not zero")
check(no_rarity["rarity_gate"] == 0 and
      "rarity_gate_enabled" in no_rarity_cfg and
      no_rarity_cfg["rarity_gate_enabled"] == 0,
      "no-rarity gate was not disabled")
check(no_rarity["cmplog_enabled"] and no_rarity["cmplog_execution_count"] > 0 and
      no_rarity_rows and {"delta_bits", "x_thrpt", "cmplog_rate"} <=
      set(no_rarity_rows[0]) and
      any(float(row["delta_bits"]) > 0.0 for row in no_rarity_rows) and
      any(float(row["x_thrpt"]) > 0.0 for row in no_rarity_rows),
      "no-rarity disabled non-rarity signals")
check(not off["cmplog_enabled"] and off["cmplog_execution_count"] == 0,
      f"CmpLog counter grew without -c: enabled={off['cmplog_enabled']} count={off['cmplog_execution_count']}")
check(matched["cmplog_enabled"] and matched["cmplog_execution_count"] > 0,
      "CmpLog counter did not grow on the actual -c path")
for name, evidence, config in (
    ("off", off, off_cfg), ("matched", matched, matched_cfg),
    ("shadow", shadow, shadow_cfg), ("full", full, full_cfg),
    ("no_a6", no_a6, no_a6_cfg), ("no_rarity", no_rarity, no_rarity_cfg),
):
    check(evidence["clean_shutdown"] is True and
          evidence["audit_schema_version"] == 1,
          f"{name} evidence was not clean or schema-stable")
    check(evidence["mode"] == config["runtime_mode"] and
          evidence["enable_a6"] == config["enable_a6"] and
          evidence["rarity_context"] == config["rarity_context_enabled"] and
          evidence["rarity_reward"] == config["rarity_reward_enabled"] and
          evidence["rarity_gate"] == config["rarity_gate_enabled"],
          f"{name} evidence/config mismatch")
check(legacy_cfg["runtime_mode"] == "active" and
      legacy_cfg["runtime_mode_explicit"] == 0 and
      legacy_cfg["enable_a6"] == 1 and
      legacy_cfg["rarity_context_enabled"] == 0 and
      legacy_cfg["rarity_reward_enabled"] == 0 and
      legacy_cfg["rarity_gate_enabled"] == 0,
      "legacy Full defaults changed")
check(legacy_empty_cfg["enable_a6"] == 1 and
      legacy_empty_cfg["context_mode"] == "dynamic",
      "legacy empty Batch A env values lost compatibility")
check(legacy_rarity_cfg["rarity_context_enabled"] == 1 and
      legacy_rarity_cfg["rarity_reward_enabled"] == 1 and
      legacy_rarity_cfg["rarity_gate_enabled"] == 1,
      "legacy rarity_mass reward did not retain rarity paths")

print(f"[+] AdaRare Batch B deterministic runtime test passed ({checks} checks)")
PY

echo "[+] Focused Batch B off/shadow/active/A6/rarity/CmpLog/evidence/fail-fast checks passed."
