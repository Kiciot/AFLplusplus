# AdaRare Bandit Scheduler (AFL++ Integration)

This document describes the **AdaRare** scheduler, a lightweight, window-based **Contextual Multi-Armed Bandit (CMAB)** designed to dynamically optimize the fuzzing strategy. It balances coverage expansion (Exploration), rarity discovery (Exploitation), and execution speed (Throughput).

## Core Model

The scheduler treats the fuzzing process as a sequential decision problem. Time is divided into discrete **windows** (default 1000ms). At the end of each window, the scheduler observes the reward, updates its internal models, and selects the strategy (Arm) for the next window.

### 1. Contextual State ()

The LinUCB model predicts the potential reward of an arm based on the current state of the fuzzing campaign. The state is a **6-dimensional vector** derived from the *previous* window's metrics:

| Dim | Metric | Description | Formula Logic |
| --- | --- | --- | --- |
| **0** | **New Bits Rate** | Speed of coverage discovery. | `log(1 + bits_per_sec) * 0.2` |
| **1** | **Rarity Rate** | Accumulation of rare edges (inverse hit counts). | `log(1 + rarity_mass_per_sec) * 0.5` |
| **2** | **Throughput** | Current execution speed. | `log(1 + execs_per_sec) * 0.2` |
| **3** | **Queue Density** | Ratio of queued items to total corpus. | `log(1 + queued / corpus) * 1.0` |
| **4** | **Favored Ratio** | Proportion of "favored" paths in queue. | `(favored / queued) * 2.0` |
| **5** | **Timeout Rate** | Stability of the target. | `log(1 + timeouts / execs) * 1.0` |

### 2. Adaptive Reward System ()

The reward quantifies how "good" a window was. It uses a **Tanh-based** formula with **Dynamic P90 Scaling** to normalize diverse metric scales (e.g., finding 1 bit vs 100 bits) into a bounded `[0, 1]` range.

**Formula:**


* ** / **: The raw rates (per second) of finding new coverage and rarity mass, amplified by the **Gate Factor**.
* ** /  (Dynamic Scaling)**: These are not fixed constants. The system uses **Reservoir Sampling** to estimate the **90th percentile (P90)** of rates observed over recent history. This ensures the `tanh` function remains sensitive regardless of whether the fuzzer is finding 1 path/sec or 1000 paths/sec.
* ** (Penalty)**: Penalizes arms that drop below the historical Exponential Moving Average (EMA) of execution speed.
* **Gate Factor**: A multiplier derived from execution signals (e.g., path length or execution time). Stronger signals boost the reward.

### 3. Arm Architecture

The scheduler controls fuzzing parameters via 6 distinct "Arms":

* **A1 - A5**: Concrete strategies with different energy/mutation characteristics.
* **A6 (Delegated Sharing Meta-Arm)**: A meta-arm. When selected, it probabilistically delegates execution to **Arm 1** or **Arm 2** based on a configured probability (`mix_p`).
* **Clipped delegated-sample sharing**: When A6 runs, the system updates **A6** with the selected meta-arm reward and gives the effective delegated arm (**A1** or **A2**) an additional clipped delegated-sample update scaled by the realized delegation probability.
* **Important terminology note**: Historical internal names such as `offpolicy`, `ips`, or `clipped_ips` are compatibility aliases. The reported mechanism is **clipped delegated-sample sharing**, not a full IPS pipeline, not an unbiased off-policy estimator, and no unexecuted arm receives synthetic reward.



## Selection Policy

The scheduler selects the next arm using a priority chain:

1. **Warmup**: Round-robin selection for the first `N` windows (default 20) to initialize statistics.
2. **Explicit Revisit**: If an arm hasn't been selected for `T` milliseconds (default 30 mins), it is forced to run. This prevents starvation and ensures models don't drift too far from reality.
3. **LinUCB (Ridge Regression)**:
* Computes the estimated reward: 
* Computes the uncertainty (exploration bonus): 
* Selects 
* *Safety*: Includes fallbacks to standard UCB1 if matrix inversion fails.



## Non-Stationary Handling

Fuzzing is a non-stationary process (finding bugs gets harder over time). AdaRare handles this via:

* **Discounting**: Every window, historical data (Matrix , Vector , Pulls) is multiplied by  (default 0.99). Recent observations matter more.
* **Matrix Clamping**: The Ridge Regression matrix  is periodically checked. If values explode,  and  are synchronously rescaled to maintain numerical stability without losing learned correlations.

## Environment Variables

Configuration is handled via environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `AFL_BANDIT` | unset | Set to `1` to enable the AdaRare/Bandit scheduler. |
| `AFL_BANDIT_WINDOW_MS` | 5000 | Duration of one decision window (ms). |
| `AFL_BANDIT_REWARD` | `novelty` | Reward source. Use `rarity_mass` for rarity-mass experiments. |
| `AFL_BANDIT_REWARD_FORMULA` | `rate_cost` | Reward formula. Supported values are `rate` and `rate_cost`. |
| `AFL_ADARARE_POLICY` | `linucb` | Scheduler policy. Supported values are `linucb`, `random_profile`, `round_robin_profile`, and `static_profile`. Profile-control policies select only A1-A5 and do not select A6. |
| `AFL_ADARARE_STATIC_ARM` | unset | Required when `AFL_ADARARE_POLICY=static_profile`. Values `1` through `5` pin the fixed profile arm A1 through A5; missing or out-of-range values fail fast. |
| `AFL_ADARARE_ALPHA` | 0.6 | LinUCB exploration parameter. Higher = more exploration. |
| `AFL_ADARARE_RIDGE` | 10.0 | Ridge regression lambda (regularization). Values below 1.0 are clamped. |
| `AFL_ADARARE_REVISIT_MS` | 180000 | Time (ms) before forcing an arm revisit (3 mins). |
| `AFL_ADARARE_MIX_P` | 0.5 | Initial Arm 6 portfolio mix probability, clamped to 0.15-0.85. |
| `AFL_ADARARE_A6_SHARING_MODE` | `clipped_delegated` | A6 sharing mode. Accepted canonical values are `fixed`, `delegated_fixed`, `inverse_prob`, `clipped_delegated`, and `clipped_delegated_sharing`. |
| `AFL_ADARARE_A6_OFFPOLICY_MODE` | legacy alias | Historical/internal compatibility alias for `AFL_ADARARE_A6_SHARING_MODE`. Old values such as `ips`, `clipped_ips`, and `clipped-ips` still map to the delegated-sharing modes above. |
| `AFL_ADARARE_GATE_MULT` | 0.02 | Strength of the Gate Amplification bonus. |
| `AFL_ADARARE_GATE_CAP` | 1.15 | Maximum gate amplification factor. |
| `AFL_ADARARE_REWARD_ALPHA` | 0.75 | Weight for Edge coverage reward. |
| `AFL_ADARARE_REWARD_BETA` | 0.20 | Weight for Rarity mass reward. |
| `AFL_ADARARE_REWARD_GAMMA` | 0.05 | Weight for Throughput penalty. |
| `AFL_ADARARE_DICT_ENABLE` | 1 | Enable dynamic dictionary probability control. |
| `AFL_ADARARE_DICT_BASELINE_PROB` | 100 | Dictionary probability before arm-specific control. |
| `AFL_ADARARE_WARMUP_PULLS` | 2.0 | Warmup pulls required per arm. |
| `AFL_ADARARE_VERIFY` | 0 | Enable verbose audit logging (`.adarare_verify.log`). |

## Observability

The scheduler produces rich telemetry in the output directory:

### 1. `.adarare_config.json`

A static snapshot of the configuration parameters and build ID used for the session. Reviewer-facing fields now use delegated-sharing terminology such as `sharing_mode`, `a6_sharing_mode`, `delegated_sharing_clip`, and `delegated_sharing_pi_eps`, while `legacy_a6_offpolicy_mode` is retained only as a compatibility label.

### 2. `.adarare_bandit.csv`

A real-time log updated every window. Key columns:

* `ts_ms`: Timestamp.
* `arm_id`: Selected arm (0-5).
* `effective_arm`: The actual strategy run (resolves A6).
* `a6_sharing_mode`: Canonical A6 sharing label such as `clipped_delegated`.
* `legacy_a6_offpolicy_mode`: Historical compatibility label such as `clipped_ips`.
* `a6_sharing_weight`: The clipped delegated-sample sharing weight applied to the effective delegated arm.
* `reward`: The final normalized reward [0,1].
* `p90_score`: Current P90 threshold used for scaling.
* `edges_term`, `rarity_term`: Components of the reward.
* `x_vc`, `x_vr`, ...: The 6 context vector values.
* `ucb_score`: The score that resulted in the selection.

## Integration Check

To verify the bandit is active, run AFL++ and check for the existence of the CSV log:

```bash
# Example Run
AFL_BANDIT=1 AFL_BANDIT_WINDOW_MS=5000 AFL_BANDIT_REWARD=rarity_mass \
  AFL_BANDIT_REWARD_FORMULA=rate_cost ./afl-fuzz -i in -o out -- ./target @@

# Verify
tail -f out/default/.adarare_bandit.csv

```
