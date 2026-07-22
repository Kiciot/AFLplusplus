# Batch B existing runtime interface audit

Base: `8224da1dce693d0a7de8d21cd9108c4e0e3a5b54`

This audit records the runtime surface present before the focused Batch B
change. It is intentionally limited to the AFL++ checkout; it does not audit
FuzzBench or any experiment host.

## Controller activation and windowing

| Existing input | Current source path | Current behavior |
| --- | --- | --- |
| `AFL_BANDIT` | `src/afl-fuzz.c`, after `read_afl_environment()` | A truthy value calls `bandit_init()`; unset or zero leaves the controller uninitialized. |
| `AFL_BANDIT_WINDOW_MS` | `src/afl-fuzz.c` | Selects the controller window; unset defaults to 5000 ms. |
| `AFL_BANDIT_REWARD` | `src/afl-fuzz.c` | Selects event, bits, novelty, or rarity-mass reward. |
| `AFL_BANDIT_REWARD_FORMULA` | `src/afl-fuzz.c` | Selects rate or rate-cost reward formulation. |
| `AFL_BANDIT_BETA`, `AFL_BANDIT_GAMMA` | `src/afl-fuzz.c` | Override legacy reward coefficients. |
| `AFL_BANDIT_TEMPORAL`, `AFL_BANDIT_LAMBDA` | `src/afl-fuzz.c` | Control temporal novelty bookkeeping. |
| `AFL_BANDIT_GATE`, `AFL_BANDIT_RHO`, `AFL_BANDIT_ALPHA`, `AFL_BANDIT_GATE_MIN` | `src/afl-fuzz.c` | Configure the existing execution/path-length gate. |
| `AFL_BANDIT_DICT`, `AFL_BANDIT_DICT_PROB_DEFAULT` | `src/afl-fuzz.c` | Control the legacy dictionary gate. |

The state defaults are initialized in `src/afl-fuzz-state.c`. The controller
deinitializes from `afl_state_deinit()` in the same file. `show_stats()` in
`src/afl-fuzz-stats.c` is the existing periodic rotation entry point.

## Batch A AdaRare profile controls

| Existing input | Current source path | Current behavior |
| --- | --- | --- |
| `AFL_ADARARE_POLICY` | `src/afl-fuzz-bandit.c:bandit_parse_profile_policy()` | Selects `linucb`, `random_profile`, `round_robin_profile`, or `static_profile`. |
| `AFL_ADARARE_ENABLE_A6` | `src/afl-fuzz-bandit.c:bandit_parse_enable_a6()` | Defaults to 1; non-LinUCB profiles require 0. |
| `AFL_ADARARE_CONTEXT_MODE` | `src/afl-fuzz-bandit.c:bandit_parse_context_mode()` | Selects `dynamic` or `constant`. |
| `AFL_ADARARE_STATIC_ARM` | `src/afl-fuzz-bandit.c:bandit_parse_static_profile_arm()` | Selects A1--A5 for `static_profile`. |
| `AFL_ADARARE_DICT_*` | `src/afl-fuzz-bandit.c:bandit_apply_arm_policy()` | Applies per-arm dictionary probabilities. |
| `AFL_ADARARE_*` reward/gate/CmpLog inputs | `src/afl-fuzz-bandit.c:bandit_init()` | Configure the existing model, reward, gate, and CmpLog reward pipeline. |

The current arm application path is
`bandit_set_owner()` -> `bandit_start_profile_control_arm()` ->
`bandit_apply_arm_policy()`. Window rotation selects the next arm and applies
that arm for the next window in `bandit_maybe_rotate()`.

## Existing rarity paths

The pre-Batch-B implementation reads rarity-related state in four runtime
areas:

1. `src/afl-fuzz-bitmap.c:has_new_bits()` computes rarity mass from
   `edge_hit`, applies the existing gate, and feeds `bandit_on_rarity_mass()`.
2. `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` derives rarity rate, the
   rarity reward term, the rarity progress alternative, and rarity-modulated
   CmpLog reward.
3. `src/afl-fuzz-bandit.c` context construction puts rarity rate in the second
   context coordinate and selection uses per-arm rarity EMA as a tie-break.
4. `src/afl-fuzz-queue.c` maintains `queue_entry.rarity_score`, samples its
   p90, and passes the normalized value to `bandit_energy_boost()`.

Coverage counters (`edge_hit`, `edge_last_seen`, and virgin maps) are also
used by non-rarity coverage bookkeeping. Batch B must gate only the rarity
consumer paths, not those normal AFL++ coverage structures.

## Existing telemetry and evidence

`bandit_log_window()` writes `.adarare_bandit.csv` and calls the existing
`.adarare_config.json` snapshot writer. `adarare_log_overhead_window()` writes
`.adarare_overhead.csv`. Both are currently reached at a controller window
boundary. CmpLog execution accounting currently has only the per-window fields
`bandit_win_cmplog_execs` and `bandit_last_cmplog_execs`; the increment is in
`src/afl-fuzz-cmplog.c:common_fuzz_cmplog_stuff()` after the actual CmpLog
target execution.

## Compatibility conclusion

Batch B reuses `AFL_BANDIT_WINDOW_MS`, all Batch A policy/context/static-arm
names, and the existing `-c` CmpLog activation path. No existing Batch A
variable is renamed. With no new mode/rarity variables, the old
`AFL_BANDIT=1` controller behavior remains the active Full profile; with no
`AFL_BANDIT`, the controller remains uninitialized.
