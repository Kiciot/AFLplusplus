# Bandit Value Model (AFL++)

This document describes the bandit value model, reward formulas, and
experimental controls for the minimal-intrusion scheduling enhancements.

## Value Model

Notation:
- NEW: set of newly covered bitmap slots for the current execution.
- hit[i]: count of times slot i was newly discovered (slot-level rarity).
- bandit_epoch: window counter incremented on each bandit window rotation.
- last_seen[i]: last bandit_epoch when slot i contributed as NEW coverage.
- dt: bandit_epoch - last_seen[i].

bandit_epoch is derived from fuzz-runtime windows (not wall-clock time) for
reproducibility; last_seen[i] is only updated when the edge contributes as NEW
coverage.

Rarity:
- rarity(i) = 1 / sqrt(hit[i] + 1)

Temporal novelty (optional):
- temporal(i) = log(1 + dt)
  or
- temporal(i) = 1 - exp(-lambda * dt)

Value for one execution:
- delta_novelty = sum_{i in NEW} rarity(i) * temporal(i)

Complexity gate (optional):
- exec_us gate (default):
  norm_exec = exec_us / max(1, ema_exec_us)
  gate = 1 / (1 + rho * max(0, norm_exec - 1))
  ema_exec_us is an EMA over exec_us (alpha≈0.01) to keep the baseline stable.
- path_len gate:
  len = count(nonzero slots)
  gate = 1 / len^alpha
- clamp: gate is clamped to [gate_min, 1.0]; gate_min defaults to 0.05 and
  is configurable.

When enabled, gate is applied to the novelty value:
- delta_novelty <- delta_novelty * gate
bandit_last_gate reports the average gate over NEW-coverage events in the last
window (falls back to 1.0 when there were no NEW events or gate=none), and
bandit_gate_samples records how many NEW events contributed.
Exec-level gate observability for dense rewards:
- bandit_last_gate_execavg: average gate across executions in the last window
  (falls back to 1.0 if no samples or gate=none).
- bandit_gate_exec_samples: number of executions sampled for gate averaging.

When using `rarity_mass`, the per-exec mass is the sum over executed slots of
1/sqrt(hit+1); it is dense (no NEW required) and still subject to the gate.
- bandit_last_rarity_samples: number of executions contributing rarity_mass in
  the last window (typically matches exec count when rarity_mass is enabled).

Rarity normalization (density):
- AFL_BANDIT_RARITY_NORM=path_len (default) uses rarity_mass / max(1,path_len)
  per exec to reduce long-path bias; `none` keeps the raw sum.
- Stats: bandit_rarity_norm, bandit_last_path_len_avg, bandit_last_rarity_density.

Havoc vs dict usage (per window):
- bandit_last_havoc_ops: count of havoc mutation attempts
- bandit_last_dict_ops: count of dict-based mutations applied
- bandit_last_dict_ratio: bandit_last_dict_ops / bandit_last_havoc_ops

## Reward

Per-window reward is dense and rate-based:

Base rate (choose one):
- event: win_new_cov / max(1, win_execs)
- bits:  win_new_bits / max(1, win_execs)
- novelty: win_novelty / max(1, win_execs)
- rarity_mass: win_rarity_mass / max(1, win_execs) where win_rarity_mass is
  the per-exec sum of 1/sqrt(hit+1) over executed slots (dense reward, no NEW
  required)

Formula options:
- rate:
  reward = base_rate
- rate_cost:
  reward = base_rate - beta * timeout_rate - gamma * slow_rate
  timeout_rate = win_timeouts / max(1, win_execs)
  slow_rate = win_slow_execs / max(1, win_execs)

Discounted-UCB (non-stationary):
- AFL_BANDIT_DISCOUNT in (0,1]; default 1.0 (no discount).
- On each window rotation, arm pulls and rewards are multiplied by the discount
  factor to forget stale history.

Warm-up windows (cold-start protection):
- AFL_BANDIT_WARMUP_WINDOWS=<u64>, default 10.
- During warm-up, arms are not changed, multipliers stay 1.0, and dict
  probability stays at the baseline default; rewards are still recorded.
- Stats: bandit_warmup_windows, bandit_in_warmup.

## Environment Variables

Bandit core:
- AFL_BANDIT=1
- AFL_BANDIT_WINDOW_MS=<ms>
- AFL_BANDIT_REWARD=event|bits|novelty
- AFL_BANDIT_REWARD=rarity_mass (dense, no NEW required)
- AFL_BANDIT_REWARD_FORMULA=rate|rate_cost
- AFL_BANDIT_BETA=<float>
- AFL_BANDIT_GAMMA=<float>

Temporal novelty:
- AFL_BANDIT_TEMPORAL=0|1
- AFL_BANDIT_LAMBDA=<float>  (0 uses log(1+dt))

Complexity gate:
- AFL_BANDIT_GATE=none|exec_us|path_len
- AFL_BANDIT_RHO=<float>    (exec_us gate strength)
- AFL_BANDIT_ALPHA=<float>  (path_len exponent)
- AFL_BANDIT_GATE_MIN=<float> (minimum gate clamp, default 0.05)
  (AFL_BANDIT_GATE=none forces gate=1.0)
- AFL_BANDIT_DISCOUNT=<float in (0,1]> (optional discounting)
- AFL_BANDIT_WARMUP_WINDOWS=<u64> (default 10)
- AFL_BANDIT_RARITY_NORM=none|path_len (default path_len)
- CmpLog observability (coarse):
  - bandit_cmplog_enabled: 1 if cmplog mode/env detected.
  - bandit_last_cmplog_execs: cmplog executions counted per bandit window
    (approximate, from cmplog path invocations).

## Observability (fuzzer_stats)

Key fields (stable schema):
- bandit_last_reward
- bandit_last_rarity_mass
- bandit_last_rarity_samples
- bandit_last_novelty
- bandit_last_new_bits
- bandit_last_execs
- bandit_last_time_us
- bandit_last_timeouts
- bandit_last_slow_execs
- bandit_reward_type
- bandit_reward_formula
- bandit_hit_max
- bandit_epoch
- bandit_temporal
- bandit_lambda
- bandit_gate
- bandit_gate_rho
- bandit_gate_alpha
- bandit_last_gate
- bandit_gate_samples
- bandit_last_gate_execavg
- bandit_gate_exec_samples
- bandit_gate_min
- bandit_exec_us_ema
- bandit_rarity_norm
- bandit_last_path_len_avg
- bandit_last_rarity_density
- bandit_build_id
- bandit_discount
- bandit_warmup_windows
- bandit_in_warmup
- bandit_cmplog_enabled
- bandit_last_cmplog_execs
- bandit_last_havoc_ops
- bandit_last_dict_ops
- bandit_last_dict_ratio

Overhead estimates:
- bandit_rotate_us_last
- bandit_rotate_us_avg
- bandit_novelty_us_last
- bandit_novelty_us_avg
- bandit_novelty_samples

These allow reporting per-window decision cost and approximate novelty
calculation overhead.

## Ablation Controls

Recommended ablations:
- Disable bandit: AFL_BANDIT=0
- Reward modes: AFL_BANDIT_REWARD=event|bits|novelty
- Reward formula: AFL_BANDIT_REWARD_FORMULA=rate|rate_cost
- Temporal novelty: AFL_BANDIT_TEMPORAL=0
- Complexity gate off: AFL_BANDIT_GATE=none

## Toy Target (Quick Sanity)

One-command example (after build):
- AFL_BANDIT=1 AFL_EXIT_ON_TIME=60 ./afl-fuzz -i experiments/toy/inputs \
  -o out/toy -- experiments/toy/target @@

See experiments/run_toy.sh for a convenience wrapper.
