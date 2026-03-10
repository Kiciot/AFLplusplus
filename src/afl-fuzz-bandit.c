/*
  AdaRare Bandit Scheduler (AFL++ integration)

  This module implements a lightweight, window-based Contextual Multi-Armed Bandit 
  (CMAB) scheduler for greybox fuzzing, specifically designed to balance coverage 
  expansion, rarity discovery, and execution throughput.

  The scheduler operates in discrete time windows. At the end of each window, it 
  evaluates the performance of the current strategy (arm), updates the underlying 
  LinUCB models, and selects the next arm.

  Key Technical Implementation Details:

  1. Contextual State (Dimensions = 6):
     The LinUCB model uses a 6-dimensional context vector derived from the previous 
     window's metrics to predict arm performance:
     - Log(New Bits Rate)
     - Log(Rarity Mass Rate)
     - Log(Execution Throughput)
     - Log(Queue Relative Density)
     - Favored Path Ratio
     - Log(Timeout Rate)

  2. Adaptive Reward System (tanh-based with Dynamic Scaling):
     Reward is calculated as: 
       Reward = alpha * tanh(EdgesRate / Scale_C1) + 
                beta  * tanh(RarityRate / Scale_C2) - 
                gamma * ThroughputPenalty
     
     * Dynamic Scaling (P90): Instead of fixed scaling factors, the system uses 
       Reservoir Sampling to estimate the 90th percentile (P90) of observed rates.
       Scale_C1 and Scale_C2 dynamically adapt to the recent distribution of 
       finding rates, ensuring the tanh inputs remain in a sensitive range.
     * Gate Amplification: Raw rates are boosted by a "Gate Factor" derived from 
       execution signal strength (log-compressed), rewarding "stronger" signals.
     * Throughput Penalty: Penalizes arms that drop below a historical Exponential 
       Moving Average (EMA) of execution speed.

  3. Arm Selection Policy (Priority Chain):
     a. Warmup: Round-robin selection during the initial windows.
     b. Explicit Revisit: Forces a selection of an arm if it hasn't been tried 
        for a configured duration (default 30 mins) to prevent starvation.
     c. LinUCB Strategy: Selects the arm with the highest Upper Confidence Bound 
        (Mean + alpha * Radius) derived from Ridge Regression (A^-1 * b).
        - Includes safety fallbacks to UCB1 if matrix inversion fails.
        - Includes clamping for matrix values and score bounds.
     d. Hierarchical Mixing (Arm A6): If Arm 6 is selected, it acts as a meta-arm, 
        probabilistically delegating to Arm 1 or Arm 2 based on a "Mix Probability".

  4. Non-Stationary Handling:
     - Discounting: Applies a discount factor (gamma < 1.0) to all historical data 
       (pulls, rewards, and LinUCB matrices A/b) every window to prioritize recent feedback.
     - Periodic Rescaling: Resets sampling reservoirs and rescales matrices to prevent 
       numerical overflow while preserving learned relationships.

  Observability:
  - Generates a per-window CSV log (.adarare_bandit.csv) detailing internal states, 
    context vectors, and reward components.
  - Dumps a static JSON configuration (.adarare_config.json) for reproducibility.
  - Optional verification log for audit trails.
*/

/*
  AdaRare Bandit Scheduler (AFL++ Integration)
  ===========================================================================
  
  模块说明:
  本模块实现了一个轻量级、基于时间窗口的上下文多臂老虎机 (Contextual MAB) 调度器，
  专门用于 Greybox Fuzzing。其核心目标是在覆盖率增长 (Exploration)、稀有路径发现 
  (Rarity) 和执行吞吐量 (Throughput) 之间寻找动态最优平衡。

  工作机制:
  调度器以离散的时间窗口 (Window) 为单位运行。在每个窗口结束时，系统会：
  1. 结算当前策略 (Arm) 的奖励 (Reward)。
  2. 更新 LinUCB 线性回归模型 (A 矩阵和 b 向量)。
  3. 基于当前上下文 (Context) 计算所有臂的置信上界 (UCB)。
  4. 选择下一个窗口的策略。

  ---------------------------------------------------------------------------
  关键技术实现细节:

  1. 上下文状态 (Contextual State, Dim=6):
     LinUCB 模型使用一个 6 维特征向量来预测臂的预期收益。特征取自上一窗口的统计值：
     [0] Log(新 Bit 发现率)        - 覆盖率增长速度
     [1] Log(稀有度 Mass 产出率)   - 稀有路径发现能力
     [2] Log(执行吞吐量)           - 基础执行效率
     [3] Log(队列相对密度)         - 种子队列拥塞程度
     [4] Favored Path 占比         - 有效种子的比例
     [5] Log(超时率)               - 路径执行稳定性

  2. 自适应奖励系统 (Adaptive Reward System):
     奖励计算公式采用 tanh 归一化，并引入了动态缩放机制：
     
       Reward = alpha * tanh(EdgesRate / Scale_C1) + 
                beta  * tanh(RarityRate / Scale_C2) - 
                gamma * ThroughputPenalty

     * 动态缩放 (Dynamic P90 Scaling): 系统使用蓄水池采样 (Reservoir Sampling) 
       实时估算发现率的第 90 百分位 (P90)。Scale_C1 和 Scale_C2 会随 Fuzzing 
       进程自动调整，防止 tanh 函数在后期因数值过小而进入线性区或数值过大而饱和。
     * 信号增强 (Gate Amplification): 原始率会乘以一个基于执行信号强度的系数，
       以奖励那些触发了更长路径或更高信号强度的输入。
     * 吞吐量惩罚 (Throughput Penalty): 如果当前吞吐量低于历史指数移动平均 (EMA)，
       将施加惩罚，防止调度器陷入执行极慢的陷阱。

  3. 臂选择策略 (Selection Policy):
     优先级链如下：
     a. 热身期 (Warmup): 初始阶段采用 Round-Robin 轮询。
     b. 强制回访 (Explicit Revisit): 若某臂在设定时间 (默认 30 分钟) 内未被选中，
        强制选中以防止“饿死”并更新其过时的统计信息。
     c. LinUCB 决策: 选择 UCB 分数 (Mean + alpha * Radius) 最高的臂。
        - 包含矩阵求逆失败时的 UCB1 降级保护。
     d. 混合臂机制 (Hierarchical Mixing - Arm A6): 
        Arm 6 是一个元策略 (Meta-Arm)，它不执行特定变异，而是根据概率 (mix_p) 
        将执行权委托给 Arm 1 或 Arm 2。

  4. 离策略学习 (Off-Policy Learning):
     当 Arm 6 被选中并委托给 Arm 1/2 时，系统执行离策略更新：
     - 同时更新 Arm 6 (Meta-Arm) 和 实际执行臂 (Effective Arm) 的模型。
     - 这最大化了样本利用率，确保底层臂在未被直接选中时也能通过 Arm 6 获得训练数据。

  5. 非平稳环境处理与数值稳定性 (Stability):
     - 折扣因子 (Discounting): 每个窗口对历史数据 (矩阵 A/b) 乘以衰减因子 
       (gamma < 1.0)，使模型更关注最近的反馈 (Recency Bias)。
     - 矩阵钳位与重缩放: 为防止 float64 溢出或精度丢失，当矩阵元素超过阈值时
       会同步缩放 A 和 b。同时对 A 的对角线实施 Ridge Lambda 钳位，保证矩阵正定性。

  ---------------------------------------------------------------------------
  可观测性 (Observability):
  - .adarare_bandit.csv: 逐窗口记录内部状态、上下文向量、奖励分量和决策结果。
  - .adarare_config.json: 记录静态配置参数以供复现。
  - .adarare_verify.log: 可选的审计日志，用于验证时间步进和随机数生成的一致性。
*/
#include "afl-fuzz.h"
#include <float.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>

/* --- Constants & Config --- */

#define BANDIT_CTX_DIM 6
#define BANDIT_SCORE_SAMPLE_N 1024
#define BANDIT_P90_MIN_SAMPLES 32

/* Normalization Sensitivity */
#define BANDIT_LOG_SCALE_FACTOR 0.2 
#define BANDIT_X0_SCALE (1.0 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X1_SCALE (2.5 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X2_SCALE (1.0 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X3_SCALE (5.0 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X4_SCALE (10.0 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X5_SCALE (5.0 * BANDIT_LOG_SCALE_FACTOR)
#define BANDIT_X_CAP 3.0

/* Gate Bonus: 5% boost per log-unit of gate value */
#define BANDIT_GATE_MULTIPLIER 0.02
#define BANDIT_GATE_CAP 1.15
#define BANDIT_PROGRESS_GATE_ENABLE 1
#define BANDIT_PROGRESS_RARITY_EPS 1e-12
#ifndef ADARARE_ZERO_PROGRESS_PENALTY
#define ADARARE_ZERO_PROGRESS_PENALTY 0.015
#endif
#ifndef ADARARE_ZERO_PROGRESS_PENALTY_STAG_MUL
#define ADARARE_ZERO_PROGRESS_PENALTY_STAG_MUL 0.50
#endif
#ifndef ADARARE_THRPT_PEN_IF_PROGRESS
#define ADARARE_THRPT_PEN_IF_PROGRESS 0.10
#endif
#ifndef ADARARE_GATE_POS_EPS
#define ADARARE_GATE_POS_EPS 1e-4
#endif
#ifndef ADARARE_REWARD_NEG_CAP
#define ADARARE_REWARD_NEG_CAP 0.25
#endif
#ifndef ADARARE_REWARD_POS_CAP
#define ADARARE_REWARD_POS_CAP 1.25
#endif
#ifndef ADARARE_CTX_EMA_ALPHA
#define ADARARE_CTX_EMA_ALPHA 0.30
#endif

/* Pulls-based warmup before LinUCB scoring. */
#define BANDIT_WARMUP_PULLS_PER_ARM 2.0

/* Coverage-first score tie-breaks. */
#define ADARARE_ENABLE_TIE_BREAK 1
#define ADARARE_TIE_EPS 0.05
#ifndef ADARARE_TIE_EPS_REL
#define ADARARE_TIE_EPS_REL 0.015
#endif
#define ADARARE_EDGES_EMA_ALPHA 0.1
#ifndef ADARARE_EARLY_EDGES_PULLS_CUTOFF
#define ADARARE_EARLY_EDGES_PULLS_CUTOFF 200.0
#endif
#ifndef ADARARE_MIN_DWELL_WINDOWS
#define ADARARE_MIN_DWELL_WINDOWS 1
#endif
#ifndef ADARARE_DWELL_EMERGENCY_ZP_STREAK
#define ADARARE_DWELL_EMERGENCY_ZP_STREAK 3U
#endif
#define ADARARE_WINDOW_MS_EARLY 4500ULL
#define ADARARE_WINDOW_MS_LATE 8000ULL
#define ADARARE_WINDOW_EARLY_ROUNDS 40U
#define ADARARE_ZP_STREAK_START 3
#define ADARARE_ZP_STEP 0.05
#define ADARARE_ZP_FACTOR_MIN 0.80

/* Stagnation controls (5s window -> 24 windows ~= 2 minutes). */
#define BANDIT_STAG_WINDOWS 24U
#define BANDIT_STAG_BOOST 1.35
#define BANDIT_STAG_TREND_ALPHA 0.2
#define BANDIT_STAG_SLOPE_ALPHA 0.25
#define BANDIT_STAG_REWARD_SLOPE_EPS 0.002
#define BANDIT_STAG_EDGES_SLOPE_EPS 0.005
#define BANDIT_STAG_TREND_MIN_WINDOWS 8U
#ifndef ADARARE_STAG_DYN_ENABLE
#define ADARARE_STAG_DYN_ENABLE 1
#endif
#ifndef ADARARE_STAG_DYN_R1
#define ADARARE_STAG_DYN_R1 2000.0
#endif
#ifndef ADARARE_STAG_DYN_R2
#define ADARARE_STAG_DYN_R2 10000.0
#endif
#ifndef ADARARE_STAG_DYN_M1
#define ADARARE_STAG_DYN_M1 3U
#endif
#ifndef ADARARE_STAG_DYN_M2
#define ADARARE_STAG_DYN_M2 8U
#endif

/* Selection-side throughput guardrail for slow arms. */
#define BANDIT_SEL_THRPT_GUARD 1
#define BANDIT_THRPT_GUARD_RATIO 0.70
#define BANDIT_THRPT_GUARD_SOFT_K 0.35
#define BANDIT_THRPT_GUARD_PENALTY_MIN 0.80
#define BANDIT_THRPT_GUARD_STREAK_START 2U
#define BANDIT_THRPT_GUARD_STREAK_STEP 0.03

/* Stagnation-triggered revisit cooldown. */
#define BANDIT_REVISIT_COOLDOWN_MS (3ULL * 60ULL * 1000ULL)

/* Safety Constraints */
#define BANDIT_PULLS_EPSILON 1e-6
#define BANDIT_BONUS_CAP 2.0

/* Keep interval comfortably above BANDIT_P90_MIN_SAMPLES so P90 scaling stays active. */
#define BANDIT_RESCALE_INTERVAL 256
#ifndef ADARARE_P90_SIGNAL_EPS
#define ADARARE_P90_SIGNAL_EPS 1e-9
#endif

#define BANDIT_MATRIX_VAL_CAP 1.0e12
#define BANDIT_MATRIX_RESCALE_FACTOR 1.0e-6 /* Keep scaled entries in same order
                                               as ridge_lambda magnitude after
                                               rescale; diagonal is clamped to
                                               ridge_lambda to keep conditioning. */
/* Keep ETA at 1.0 unless selections accounting is redesigned for fractional credit. */
#define ADARARE_A6_BASE_ETA 1.0
#define ADARARE_ENABLE_ADAPTIVE_A6 1
#define ADARARE_A6_MIX_EMA_ALPHA 0.2
#define ADARARE_A6_TOPK 2
#define ADARARE_A6_SOFTMAX_TEMP 1.20
#ifndef ADARARE_A6_PI_FLOOR_FRAC
#define ADARARE_A6_PI_FLOOR_FRAC 0.05
#endif
#define ADARARE_MIX_P_MIN 0.15
#define ADARARE_MIX_P_MAX 0.85
#define ADARARE_MIX_UPDATE_INTERVAL 4U
#ifndef ADARARE_A6_MIX_UPDATE_MIN_QSUM
#define ADARARE_A6_MIX_UPDATE_MIN_QSUM 0.05
#endif
#ifndef ADARARE_A6_MIX_RETURN_RATE
#define ADARARE_A6_MIX_RETURN_RATE 0.02
#endif
#ifndef ADARARE_A6_MIX_EMA
#define ADARARE_A6_MIX_EMA 0.20
#endif
#ifndef ADARARE_A6_MIX_MIN_SAMPLES
#define ADARARE_A6_MIX_MIN_SAMPLES 16ULL
#endif
#ifndef ADARARE_A6_MIX_TANH_SCALE
#define ADARARE_A6_MIX_TANH_SCALE 0.05
#endif
#ifndef ADARARE_A6_OFFPOLICY_MODE_DEFAULT
#define ADARARE_A6_OFFPOLICY_MODE_DEFAULT BANDIT_A6_OFFPOLICY_CLIPPED_IPS
#endif
#define ADARARE_ENABLE_IPS 1
#define ADARARE_IPS_CLIP 2.0
#define ADARARE_IPS_PI_EPS 1e-6
#ifndef ADARARE_ENABLE_IPS_STATS
#define ADARARE_ENABLE_IPS_STATS 1
#endif
#ifndef ADARARE_ENABLE_IPS_MODEL
#define ADARARE_ENABLE_IPS_MODEL 0
#endif
#ifndef ADARARE_IPS_MODEL_CLIP
#define ADARARE_IPS_MODEL_CLIP 1.0
#endif
#define BANDIT_BUILD_ID_AUDIT 1

#ifndef ADARARE_BUILD_ID
#define ADARARE_BUILD_ID "unknown"
#endif
static const char adarare_build_id_anchor[] __attribute__((used)) =
    "adarare-build:" ADARARE_BUILD_ID;

/* --- Helper Structures --- */

static u8 bandit_dbg = 0;
static u8 bandit_dbg_inited = 0;
static u8 bandit_dbg_fp_inited = 0;
static u8 bandit_build_id_logged = 0;
static FILE *bandit_dbg_fp = NULL;

static inline const char *adarare_build_id_effective(void) {
  const char *env_build_id = getenv("AFL_ADARARE_BUILD_ID");
  return (env_build_id && env_build_id[0]) ? env_build_id : ADARARE_BUILD_ID;
}

typedef struct {
    double samples[BANDIT_SCORE_SAMPLE_N];
    u64 count;
    u64 seen;
} bandit_reservoir_t;

static void reservoir_reset(bandit_reservoir_t *res) {
    if (!res) return;
    res->count = 0;
    res->seen = 0;
}

static void reservoir_add(bandit_reservoir_t *res, double val, u32 r1, u32 r2) {
    if (!res) return;
    res->seen++;
    if (res->count < BANDIT_SCORE_SAMPLE_N) {
        res->samples[res->count++] = val;
    } else {
        u64 rnd64 = ((u64)r1 << 32) | (u64)r2;
        u64 idx = rnd64 % res->seen;
        if (idx < BANDIT_SCORE_SAMPLE_N) {
            res->samples[idx] = val;
        }
    }
}

static int cmp_double(const void *a, const void *b) {
  double da = *(const double *)a;
  double db = *(const double *)b;
  if (da < db) return -1;
  if (da > db) return 1;
  return 0;
}

static double reservoir_p90(bandit_reservoir_t *res) {
    if (!res || res->count == 0) return 0.0;
    
    double tmp[BANDIT_SCORE_SAMPLE_N]; 
    memcpy(tmp, res->samples, res->count * sizeof(double));
    
    qsort(tmp, res->count, sizeof(double), cmp_double);
    
    u32 idx = (u32)floor(0.9 * (double)(res->count - 1));
    if (idx >= res->count) idx = res->count - 1;
    
    double val = tmp[idx];
    if (val < 1e-12) val = 0.0;
    return val;
}

/* --- JSON Helper --- */

static void json_print_escaped(FILE *fp, const char *str) {
    if (!str) { fprintf(fp, "null"); return; }
    fputc('"', fp);
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '\"': fprintf(fp, "\\\""); break;
            case '\\': fprintf(fp, "\\\\"); break;
            case '\b': fprintf(fp, "\\b"); break;
            case '\f': fprintf(fp, "\\f"); break;
            case '\n': fprintf(fp, "\\n"); break;
            case '\r': fprintf(fp, "\\r"); break;
            case '\t': fprintf(fp, "\\t"); break;
            default:
                if (isprint((unsigned char)*p)) {
                    fputc(*p, fp);
                } else {
                    fprintf(fp, "\\u%04x", (unsigned char)*p);
                }
        }
    }
    fputc('"', fp);
}

/* --- Core Logic --- */

static inline u32 bandit_default_arm_count(void) { return AFL_BANDIT_MAX_ARMS; }

typedef enum {
  BANDIT_ENERGY_LOG = 0,
  BANDIT_ENERGY_LINEAR_SOFT,
  BANDIT_ENERGY_LINEAR_MED,
  BANDIT_ENERGY_THRESHOLD,
  BANDIT_ENERGY_FLAT
} bandit_energy_mode_t;

typedef struct {
  const char *name;
  u32 dict_prob;
  double havoc_stack_mul;
  s8 prefer_favored;
  u8 prefer_new;
  u8 trim_policy; /* 0 keep, 1 force disable trim, 2 force enable trim */
  bandit_energy_mode_t energy_boost_mode;
  double w_alpha;
  double w_beta;
  double w_gamma;
  double w_delta;
  double zp_penalty_mul;
} bandit_arm_cfg_t;

static const bandit_arm_cfg_t kArmCfg[AFL_BANDIT_MAX_ARMS] = {
    [BANDIT_ARM_A1] = {
        .name = "A1 throughput-first havoc",
        .dict_prob = 5,
        .havoc_stack_mul = 1.20,
        .prefer_favored = 0,
        .prefer_new = 1,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_LINEAR_SOFT,
        .w_alpha = 0.55,
        .w_beta = 0.15,
        .w_gamma = 0.30,
        .w_delta = 0.0, /* 0 -> inherit global reward_delta */
        .zp_penalty_mul = 1.10,
    },
    [BANDIT_ARM_A2] = {
        .name = "A2 dictionary-heavy",
        .dict_prob = 45,
        .havoc_stack_mul = 1.05,
        .prefer_favored = 0,
        .prefer_new = 0,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_LOG,
        .w_alpha = 0.35,
        .w_beta = 0.50,
        .w_gamma = 0.15,
        .w_delta = 0.0, /* 0 -> inherit global reward_delta */
        .zp_penalty_mul = 0.90,
    },
    [BANDIT_ARM_A3] = {
        .name = "A3 cmplog-synergy",
        .dict_prob = 20,
        .havoc_stack_mul = 1.10,
        .prefer_favored = 1,
        .prefer_new = 0,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_LINEAR_MED,
        .w_alpha = 0.45,
        .w_beta = 0.40,
        .w_gamma = 0.15,
        .w_delta = 0.70, /* cmplog-synergy arm: stronger continuous cmp term */
        .zp_penalty_mul = 1.00,
    },
    [BANDIT_ARM_A4] = {
        .name = "A4 favored exploitation",
        .dict_prob = 12,
        .havoc_stack_mul = 1.18,
        .prefer_favored = 1,
        .prefer_new = 0,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_THRESHOLD,
        .w_alpha = 0.70,
        .w_beta = 0.20,
        .w_gamma = 0.10,
        .w_delta = 0.0, /* 0 -> inherit global reward_delta */
        .zp_penalty_mul = 1.00,
    },
    [BANDIT_ARM_A5] = {
        .name = "A5 queue exploration",
        .dict_prob = 8,
        .havoc_stack_mul = 0.95,
        .prefer_favored = -1,
        .prefer_new = 1,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_FLAT,
        .w_alpha = 0.40,
        .w_beta = 0.35,
        .w_gamma = 0.25,
        .w_delta = 0.0, /* 0 -> inherit global reward_delta */
        .zp_penalty_mul = 0.60,
    },
    [BANDIT_ARM_A6] = {
        .name = "A6 top-k portfolio",
        .dict_prob = 15,
        .havoc_stack_mul = 1.00,
        .prefer_favored = 0,
        .prefer_new = 0,
        .trim_policy = 0,
        .energy_boost_mode = BANDIT_ENERGY_LOG,
        .w_alpha = 0.75,
        .w_beta = 0.20,
        .w_gamma = 0.05,
        .w_delta = 0.0, /* 0 -> inherit global reward_delta */
        .zp_penalty_mul = 1.00,
    },
};

static inline const bandit_arm_cfg_t *bandit_arm_cfg_for_arm(u32 arm_idx) {
  if (arm_idx >= AFL_BANDIT_MAX_ARMS) return NULL;
  return &kArmCfg[arm_idx];
}

static inline double bandit_multiplier_for_arm(u32 arm_idx) {
  const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm_idx);
  if (!cfg || !isfinite(cfg->havoc_stack_mul) || cfg->havoc_stack_mul <= 0.0) {
    return 1.0;
  }
  return cfg->havoc_stack_mul;
}

static u64 xorshift64(u64 *state) {
    u64 x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
  *state = x;
  return x;
}

static inline u64 bandit_now_ms(void) {
  return get_cur_time_us() / 1000;
}

static inline u64 bandit_current_window_ms(const bandit_state_t *bandit) {
  if (!bandit) return AFL_BANDIT_DEFAULT_WINDOW_MS;

  u64 cur = bandit->window_ms ? bandit->window_ms : AFL_BANDIT_DEFAULT_WINDOW_MS;
  if (bandit->total_selections < ADARARE_WINDOW_EARLY_ROUNDS) {
    cur = ADARARE_WINDOW_MS_EARLY;
  } else {
    cur = ADARARE_WINDOW_MS_LATE;
  }
  if (cur < 100ULL) { cur = 100ULL; }
  return cur;
}

static inline void bandit_dbg_init(void) {

  if (bandit_dbg_inited) { return; }
  char *val = getenv("AFL_BANDIT_DEBUG");
  if (!val || !val[0]) {
    bandit_dbg = 0;
  } else {
    bandit_dbg = (strtol(val, NULL, 10) != 0) ? 1 : 0;
  }
  bandit_dbg_inited = 1;

}

static inline FILE *bandit_dbg_open_if_needed(const bandit_state_t *bandit) {

  if (bandit_dbg_fp_inited) {
    return bandit_dbg_fp ? bandit_dbg_fp : stderr;
  }
  bandit_dbg_fp_inited = 1;

  char *path = getenv("AFL_BANDIT_DEBUG_PATH");
  if (!path || !path[0]) {
    bandit_dbg_fp = NULL;
    return stderr;
  }

  const char *open_path = path;
  char resolved_path[PATH_MAX];
  struct stat st;
  if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
    if (bandit && bandit->owner && bandit->owner->out_dir &&
        bandit->owner->out_dir[0]) {
      snprintf(resolved_path, sizeof(resolved_path), "%s/.adarare_dbg.csv",
               bandit->owner->out_dir);
    } else {
      snprintf(resolved_path, sizeof(resolved_path), "%s/.adarare_dbg.csv",
               path);
    }
    open_path = resolved_path;
  }

  bandit_dbg_fp = fopen(open_path, "a");
  if (!bandit_dbg_fp) {
    bandit_dbg_fp = NULL;
    return stderr;
  }

  setvbuf(bandit_dbg_fp, NULL, _IOLBF, 0);
  return bandit_dbg_fp;

}

static inline double bandit_arm_mean_reward(const bandit_arm_state_t *arm) {

  if (!arm) { return 0.0; }
  double pulls = arm->pulls;
  if (pulls < BANDIT_PULLS_EPSILON) pulls = BANDIT_PULLS_EPSILON;
  return arm->total_reward / pulls;

}

static inline double bandit_min_warmup_pulls(const bandit_state_t *bandit) {

  if (!bandit || !bandit->arms || !bandit->num_arms) { return 0.0; }
  double min_pulls = DBL_MAX;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    double pulls = bandit->arms[i].warmup_pulls;
    if (!isfinite(pulls) || pulls < 0.0) pulls = 0.0;
    if (pulls < min_pulls) min_pulls = pulls;
  }
  return (min_pulls == DBL_MAX) ? 0.0 : min_pulls;

}

static inline u8 bandit_in_pulls_warmup(const bandit_state_t *bandit) {

  if (!bandit || !bandit->arms) { return 0; }
  double target = bandit->warmup_pulls_target;
  if (!isfinite(target) || target <= BANDIT_PULLS_EPSILON) { return 0; }
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    if (bandit->arms[i].warmup_pulls + BANDIT_PULLS_EPSILON < target) {
      return 1;
    }
  }
  return 0;

}

static inline u32 bandit_argmin_pulls(const bandit_state_t *bandit) {

  if (!bandit || !bandit->arms || !bandit->num_arms) { return 0; }
  u32 best_arm = 0;
  double best_pulls = DBL_MAX;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    double pulls = bandit->arms[i].warmup_pulls;
    if (!isfinite(pulls) || pulls < 0.0) pulls = 0.0;
    if (pulls + BANDIT_PULLS_EPSILON < best_pulls ||
        (fabs(pulls - best_pulls) <= BANDIT_PULLS_EPSILON &&
         i < best_arm)) {
      best_pulls = pulls;
      best_arm = i;
    }
  }
  return best_arm;

}

static inline u32 bandit_pick_revisit_arm(const bandit_state_t *bandit) {

  if (!bandit || !bandit->arms || !bandit->num_arms) { return 0; }

  u32 best_arm = bandit->current_arm;
  double best_mean = -DBL_MAX;
  u8 found_non_current = 0;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    if (i == bandit->current_arm) { continue; }
    double mean = bandit_arm_mean_reward(&bandit->arms[i]);
    if (mean > best_mean) {
      best_mean = mean;
      best_arm = i;
      found_non_current = 1;
    }
  }

  if (found_non_current) { return best_arm; }

  best_arm = 0;
  best_mean = -DBL_MAX;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    double mean = bandit_arm_mean_reward(&bandit->arms[i]);
    if (mean > best_mean) {
      best_mean = mean;
      best_arm = i;
    }
  }
  return best_arm;

}

static inline double bandit_a6_choice_prob(const bandit_state_t *bandit,
                                           u32 arm) {

  if (!bandit) return 0.0;
  for (u32 k = 0; k < ADARARE_A6_TOPK && k < AFL_BANDIT_MAX_ARMS; ++k) {
    if (bandit->a6_topk[k] == arm) {
      double p = bandit->a6_topk_prob[k];
      if (!isfinite(p) || p < 0.0) return 0.0;
      return p;
    }
  }
  return 0.0;

}

static void bandit_build_a6_topk(bandit_state_t *bandit) {

  if (!bandit || !bandit->arms || !bandit->num_arms) return;
  bandit->last_a6_pi_floor = 0.0;

  double qvals[ADARARE_A6_TOPK];
  u32 filled = 0;
  for (u32 k = 0; k < ADARARE_A6_TOPK && k < AFL_BANDIT_MAX_ARMS; ++k) {
    bandit->a6_topk[k] = 0;
    bandit->a6_topk_prob[k] = 0.0;
    qvals[k] = -DBL_MAX;
  }

  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    if (i == BANDIT_ARM_A6) continue;

    double q = bandit_arm_mean_reward(&bandit->arms[i]);
    if (!isfinite(q)) q = 0.0;

    u32 pos = filled;
    while (pos > 0 && q > qvals[pos - 1]) {
      pos--;
    }

    if (pos >= ADARARE_A6_TOPK) {
      if (filled < ADARARE_A6_TOPK) filled++;
      continue;
    }

    u32 limit = (filled < ADARARE_A6_TOPK) ? filled : (ADARARE_A6_TOPK - 1);
    for (u32 j = limit; j > pos; --j) {
      qvals[j] = qvals[j - 1];
      bandit->a6_topk[j] = bandit->a6_topk[j - 1];
    }

    qvals[pos] = q;
    bandit->a6_topk[pos] = i;
    if (filled < ADARARE_A6_TOPK) filled++;
  }

  if (filled == 0) {
    u32 fallback = 0;
    if (fallback == BANDIT_ARM_A6 && bandit->num_arms > 1) fallback = 1;
    if (fallback >= bandit->num_arms) fallback = 0;
    bandit->a6_topk[0] = fallback;
    qvals[0] = 0.0;
    filled = 1;
  }

  double temp = ADARARE_A6_SOFTMAX_TEMP;
  if (!isfinite(temp) || temp <= 1e-6) temp = 0.25;
  double maxq = qvals[0];
  for (u32 k = 1; k < filled; ++k) {
    if (qvals[k] > maxq) maxq = qvals[k];
  }

  double sumw = 0.0;
  for (u32 k = 0; k < filled; ++k) {
    double z = (qvals[k] - maxq) / temp;
    double w = exp(z);
    if (!isfinite(w) || w < 0.0) w = 0.0;
    bandit->a6_topk_prob[k] = w;
    sumw += w;
  }

  double floor_frac = ADARARE_A6_PI_FLOOR_FRAC;
  if (!isfinite(floor_frac) || floor_frac < 0.0) floor_frac = 0.0;
  if (floor_frac > 1.0) floor_frac = 1.0;
  double pi_floor = 0.0;
  if (filled > 0) {
    pi_floor = floor_frac / (double)filled;
    if (!isfinite(pi_floor) || pi_floor < 0.0) pi_floor = 0.0;
  }
  bandit->last_a6_pi_floor = pi_floor;

  /* first normalize */
  if (!isfinite(sumw) || sumw <= 0.0) {
    double uniform = 1.0 / (double)filled;
    for (u32 k = 0; k < filled; ++k) {
      bandit->a6_topk_prob[k] = uniform;
    }
  } else {
    for (u32 k = 0; k < filled; ++k) {
      bandit->a6_topk_prob[k] /= sumw;
    }
  }

  /* apply floor */
  double sum2 = 0.0;
  for (u32 k = 0; k < filled; ++k) {
    if (bandit->a6_topk_prob[k] < pi_floor) {
      bandit->a6_topk_prob[k] = pi_floor;
    }
    sum2 += bandit->a6_topk_prob[k];
  }

  /* renormalize */
  if (sum2 > 0.0) {
    for (u32 k = 0; k < filled; ++k) {
      bandit->a6_topk_prob[k] /= sum2;
    }
  }

  for (u32 k = filled; k < ADARARE_A6_TOPK && k < AFL_BANDIT_MAX_ARMS; ++k) {
    bandit->a6_topk[k] = bandit->a6_topk[0];
    bandit->a6_topk_prob[k] = 0.0;
  }

}

static void bandit_dbg_log_window(
    const bandit_state_t *bandit, u64 now_ms, u64 cur_window_ms,
    u64 win_total_ms, u32 arm_cur,
    u32 arm_next, const double arm_weights[AFL_BANDIT_MAX_ARMS],
    const double score_pred[AFL_BANDIT_MAX_ARMS],
    const double score_bonus[AFL_BANDIT_MAX_ARMS],
    const double score_total[AFL_BANDIT_MAX_ARMS],
    const double score_guard_ratio[AFL_BANDIT_MAX_ARMS],
    const double score_guard_factor[AFL_BANDIT_MAX_ARMS],
    const u32 score_guard_streak[AFL_BANDIT_MAX_ARMS],
    const double score_zp_factor[AFL_BANDIT_MAX_ARMS],
    const u8 score_zp_applied[AFL_BANDIT_MAX_ARMS], u32 tie_break_hits,
    double edges_rate, double rarity_rate, double edges_per_exec,
    double rarity_per_exec, double p90_edges, double p90_rarity, double scale_c1,
    double scale_c2, u32 scale_arm, double penalty, double gate_factor,
    double gate_bonus, double gate_bonus_final, double gate_bonus_eff,
    double zero_prog_pen,
    u8 has_progress, u8 stag_bonus_boost, u8 dwell_blocked,
    double raw_reward, double final_reward, const double raw_x[BANDIT_CTX_DIM],
    const double smooth_x[BANDIT_CTX_DIM], u8 forced_revisit) {

  bandit_dbg_init();
  if (!bandit_dbg || !bandit || !bandit->arms) { return; }
  FILE *dbg_out = bandit_dbg_open_if_needed(bandit);
  if (!dbg_out) { return; }

  double wsum = 0.0;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    wsum += arm_weights ? arm_weights[i] : 0.0;
  }

  fprintf(dbg_out,
          "[bandit dbg] now_ms=%llu window_ms=%llu arm_cur=%u arm_next=%u "
          "arm_eff=%u warmup=%u stag_windows=%u dyn_stag_thresh=%u trend_stag=%u "
          "warmup_target=%.4f warmup_min=%.4f discount=%.6f "
          "slope_r=%.6f slope_e=%.6f stag_bonus_boost=%u forced_revisit=%u "
          "win_total_ms=%llu w_sum=%.4f new_cov=%llu new_bits=%llu "
          "clamp_hi=%u guard_hits=%u tie_win=%u tie_total=%llu "
          "tie_det_win=%llu tie_det_total=%llu tie_eps=%.6f reward_zero=%u "
          "dwell_windows=%u dwell_blocked=%u dwell_emergency_zero=%u\n",
          (unsigned long long)now_ms, (unsigned long long)cur_window_ms,
          arm_cur, arm_next, bandit->current_arm_eff, (unsigned)bandit->in_warmup,
          bandit->stagnation_windows, bandit->last_dyn_stag_thresh,
          (unsigned)bandit->stag_trend_active,
          bandit->warmup_pulls_target, bandit->last_warmup_min_pulls,
          bandit->discount,
          bandit->stag_slope_reward, bandit->stag_slope_edges,
          (unsigned)stag_bonus_boost, forced_revisit,
          (unsigned long long)win_total_ms, wsum,
          (unsigned long long)bandit->win_new_cov,
          (unsigned long long)bandit->win_new_bits, bandit->last_win_clamp_hi,
          bandit->last_win_guard_hits, tie_break_hits,
          (unsigned long long)bandit->tie_break_hits_total,
          (unsigned long long)bandit->tie_break_det_hits_win,
          (unsigned long long)bandit->tie_break_det_hits_total,
          bandit->last_tie_eps,
          (unsigned)bandit->last_win_reward_zero, bandit->dwell_windows,
          (unsigned)dwell_blocked, (unsigned)bandit->last_dwell_emergency_zero);

  fprintf(dbg_out,
          "[bandit dbg] reward edges_rate=%.6f rarity_rate=%.6f penalty=%.6f "
          "edges_per_exec=%.6f rarity_per_exec=%.6f "
          "thrpt_pen=%.6f thrpt_pen_eff=%.6f gate_factor=%.6f gate_bonus=%.6f "
          "gate_progress_gated=%u gate_headroom=%.6f gate_inject=%.6f "
          "zero_prog_pen=%.6f raw_reward_pre_cap=%.6f raw_reward=%.6f final_reward=%.6f "
          "has_progress=%u gate_bonus_final=%.6f gate_bonus_eff=%.6f p90_arm=%u "
          "p90_edges=%.6f p90_rarity=%.6f scale_c1=%.6f "
          "scale_c2=%.6f p90_add_edges=%u p90_add_rarity=%u\n",
          edges_rate, rarity_rate, penalty, edges_per_exec, rarity_per_exec,
          bandit->last_thrpt_pen, bandit->last_thrpt_pen_eff, gate_factor,
          gate_bonus, (unsigned)bandit->last_gate_progress_gated,
          bandit->last_gate_bonus_headroom, bandit->last_gate_bonus_inject,
          zero_prog_pen, bandit->last_raw_reward_pre_cap, raw_reward,
          final_reward,
          (unsigned)has_progress, gate_bonus_final, gate_bonus_eff, scale_arm,
          p90_edges,
          p90_rarity, scale_c1, scale_c2, (unsigned)bandit->last_p90_add_edges,
          (unsigned)bandit->last_p90_add_rarity);

  fprintf(dbg_out,
          "[bandit dbg] a6 mix_p=%.6f a6_to_a1=%llu a6_to_a2=%llu "
          "a6_q1=%.6f a6_q2=%.6f a6_pi=%.6f a6_eta_eff=%.6f "
          "a6_pi_floor=%.6f "
          "a6_eta_stats=%.6f a6_eta_model=%.6f "
          "a6_choice=%u a6_choice_pi=%.6f "
          "a6_k0=%u a6_k1=%u a6_k2=%u a6_p0=%.6f a6_p1=%.6f a6_p2=%.6f\n",
          bandit->mix_p, (unsigned long long)bandit->a6_to_a1,
          (unsigned long long)bandit->a6_to_a2, bandit->a6_q1, bandit->a6_q2,
          bandit->last_a6_pi_eff, bandit->last_a6_eta_eff,
          bandit->last_a6_pi_floor,
          bandit->last_a6_eta_stats, bandit->last_a6_eta_model,
          bandit->last_a6_choice, bandit->a6_choice_pi, bandit->a6_topk[0],
          bandit->a6_topk[1], bandit->a6_topk[2], bandit->a6_topk_prob[0],
          bandit->a6_topk_prob[1], bandit->a6_topk_prob[2]);

  const double *raw_ctx = raw_x ? raw_x : bandit->last_raw_x;
  const double *smooth_ctx = smooth_x ? smooth_x : bandit->last_x;
  fprintf(dbg_out,
          "[bandit dbg] ctx raw_x0=%.6f raw_x1=%.6f raw_x2=%.6f raw_x3=%.6f "
          "raw_x4=%.6f raw_x5=%.6f x0=%.6f x1=%.6f x2=%.6f x3=%.6f x4=%.6f "
          "x5=%.6f\n",
          raw_ctx[0], raw_ctx[1], raw_ctx[2], raw_ctx[3], raw_ctx[4],
          raw_ctx[5], smooth_ctx[0], smooth_ctx[1], smooth_ctx[2], smooth_ctx[3],
          smooth_ctx[4], smooth_ctx[5]);

  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    double pulls = bandit->arms[i].pulls;
    double mean = bandit_arm_mean_reward(&bandit->arms[i]);
    double w = arm_weights ? arm_weights[i] : 0.0;
    double pred = score_pred ? score_pred[i] : NAN;
    double bonus = score_bonus ? score_bonus[i] : NAN;
    double score = score_total ? score_total[i] : NAN;
    double guard_ratio = score_guard_ratio ? score_guard_ratio[i] : 1.0;
    double guard_factor = score_guard_factor ? score_guard_factor[i] : 1.0;
    u32 guard_streak = score_guard_streak ? score_guard_streak[i] : 0;
    double zp_factor = score_zp_factor ? score_zp_factor[i] : 1.0;
    u8 zp_applied = score_zp_applied ? score_zp_applied[i] : 0;
    u32 zp_streak = bandit->arms[i].zp_streak;
    u32 guard_on =
        (isfinite(guard_factor) &&
         guard_factor + BANDIT_PULLS_EPSILON < 1.0) ? 1U : 0U;
    double arm_thrpt = bandit->arms[i].last_thrpt;
    double edges_ema = bandit->arms[i].edges_ema;
    double early_edges_ema = bandit->arms[i].early_edges_ema;
    double edges_per_exec_ema = bandit->arms[i].edges_per_exec_ema;
    double rarity_per_exec_ema = bandit->arms[i].rarity_per_exec_ema;

    if (isfinite(pred) && isfinite(bonus) && isfinite(score)) {
      fprintf(dbg_out,
              "[bandit dbg] arm=%u(%s) w=%.4f pulls=%.4f mean=%.6f "
              "pred=%.6f bonus=%.6f score=%.6f guard=%u guard_ratio=%.4f "
              "guard_factor=%.4f guard_streak=%u arm_thrpt=%.6f "
              "edges_ema=%.6f early_edges_ema=%.6f "
              "edges_per_exec_ema=%.6f rarity_per_exec_ema=%.6f "
              "zp_streak=%u zp_factor=%.4f zp_applied=%u\n",
              i, bandit_arm_label(i), w, pulls, mean, pred, bonus, score,
              guard_on, guard_ratio, guard_factor, guard_streak, arm_thrpt,
              edges_ema, early_edges_ema, edges_per_exec_ema,
              rarity_per_exec_ema, zp_streak, zp_factor, (unsigned)zp_applied);
    } else {
      fprintf(dbg_out,
              "[bandit dbg] arm=%u(%s) w=%.4f pulls=%.4f mean=%.6f "
              "guard=%u guard_ratio=%.4f guard_factor=%.4f guard_streak=%u "
              "arm_thrpt=%.6f edges_ema=%.6f early_edges_ema=%.6f "
              "edges_per_exec_ema=%.6f rarity_per_exec_ema=%.6f "
              "zp_streak=%u zp_factor=%.4f zp_applied=%u\n",
              i, bandit_arm_label(i), w, pulls, mean, guard_on, guard_ratio,
              guard_factor, guard_streak, arm_thrpt, edges_ema,
              early_edges_ema, edges_per_exec_ema, rarity_per_exec_ema,
              zp_streak, zp_factor, (unsigned)zp_applied);
    }
  }

  fflush(dbg_out);

}

static u32 bandit_get_random(bandit_state_t *bandit) {
  if (!bandit) { return (u32)(get_cur_time_us() >> 32); }
  if (!bandit->rng_state) bandit->rng_state = 1;
  u32 val = (u32)(xorshift64(&bandit->rng_state) >> 32);
  if (bandit->verify_enabled && bandit->rng_log_idx < 32) {
    bandit->rng_log[bandit->rng_log_idx++] = val;
  }
  return val;
}

static inline u32 bandit_effective_arm(u32 arm, u8 mix_choice) {

  if (arm == BANDIT_ARM_A6) {
    if (mix_choice < AFL_BANDIT_MAX_ARMS && mix_choice != BANDIT_ARM_A6) {
      return (u32)mix_choice;
    }
    return BANDIT_ARM_A1;
  }

  return arm;

}

static inline void bandit_win_account(bandit_state_t *bandit, u64 now_ms) {

  if (!bandit || !bandit->enabled) { return; }

  if (!bandit->win_last_ts) {
    bandit->win_last_ts = now_ms;
    bandit->win_last_arm = bandit->current_arm;
    return;
  }

  if (now_ms > bandit->win_last_ts) {
    u64 dt = now_ms - bandit->win_last_ts;
    if (bandit->win_last_arm < bandit->num_arms &&
        bandit->win_last_arm < AFL_BANDIT_MAX_ARMS) {
      bandit->win_arm_ms[bandit->win_last_arm] += dt;
    }
  }

  bandit->win_last_ts = now_ms;
  bandit->win_last_arm = bandit->current_arm;

}

static int invert6(const double m[BANDIT_CTX_DIM][BANDIT_CTX_DIM], double out[BANDIT_CTX_DIM][BANDIT_CTX_DIM]) {
  double aug[BANDIT_CTX_DIM][BANDIT_CTX_DIM * 2];
  for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
    for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
      aug[r][c] = m[r][c];
      aug[r][c + BANDIT_CTX_DIM] = (r == c) ? 1.0 : 0.0;
    }
  }
  for (int i = 0; i < BANDIT_CTX_DIM; ++i) {
    double pivot = aug[i][i];
    int pivot_r = i;
    for (int r = i + 1; r < BANDIT_CTX_DIM; ++r) {
      if (fabs(aug[r][i]) > fabs(pivot)) {
        pivot = aug[r][i];
        pivot_r = r;
      }
    }
    if (fabs(pivot) < 1e-12) return 0;
    if (pivot_r != i) {
      for (int c = i; c < BANDIT_CTX_DIM * 2; ++c) {
        double tmp = aug[i][c];
        aug[i][c] = aug[pivot_r][c];
        aug[pivot_r][c] = tmp;
      }
    }
    pivot = aug[i][i];
    double inv_p = 1.0 / pivot;
    for (int c = i; c < BANDIT_CTX_DIM * 2; ++c) aug[i][c] *= inv_p;
    for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
      if (r == i) continue;
      double factor = aug[r][i];
      if (factor == 0.0) continue;
      for (int c = i; c < BANDIT_CTX_DIM * 2; ++c) {
        aug[r][c] -= factor * aug[i][c];
      }
    }
  }
  for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
    for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
      out[r][c] = aug[r][c + BANDIT_CTX_DIM];
    }
  }
  return 1;
}

static double bandit_env_double(const char *key, double def, double minv,
                                double maxv) {
  char *val = getenv(key);
  if (!val) return def;
  char *end = NULL;
  double v = strtod(val, &end);
  if (end == val) return def;
  if (v < minv) v = minv;
  if (v > maxv) v = maxv;
  return v;
}

static u64 bandit_env_u64(const char *key, u64 def, u64 minv, u64 maxv) {
  char *val = getenv(key);
  if (!val) return def;
  char *end = NULL;
  unsigned long long v = strtoull(val, &end, 10);
  if (end == val) return def;
  if (v < minv) v = minv;
  if (v > maxv) v = maxv;
  return (u64)v;
}

static int bandit_env_int(const char *key, int def, int minv, int maxv) {
  char *val = getenv(key);
  if (!val) return def;
  char *end = NULL;
  long v = strtol(val, &end, 10);
  if (end == val) return def;
  if (v < minv) v = minv;
  if (v > maxv) v = maxv;
  return (int)v;
}

static inline u8 bandit_parse_a6_offpolicy_mode(void) {

  char *val = getenv("AFL_ADARARE_A6_OFFPOLICY_MODE");
  if (!val || !val[0]) {
    return (u8)bandit_env_int("AFL_ADARARE_A6_OFFPOLICY_MODE",
                              ADARARE_A6_OFFPOLICY_MODE_DEFAULT,
                              BANDIT_A6_OFFPOLICY_FIXED,
                              BANDIT_A6_OFFPOLICY_CLIPPED_IPS);
  }

  if ((val[0] >= '0' && val[0] <= '9') || val[0] == '+' || val[0] == '-') {
    int mode = bandit_env_int("AFL_ADARARE_A6_OFFPOLICY_MODE",
                              ADARARE_A6_OFFPOLICY_MODE_DEFAULT,
                              BANDIT_A6_OFFPOLICY_FIXED,
                              BANDIT_A6_OFFPOLICY_CLIPPED_IPS);
    return (u8)mode;
  }

  char norm[32];
  size_t i = 0;
  while (val[i] && i + 1 < sizeof(norm)) {
    norm[i] = (char)tolower((unsigned char)val[i]);
    i++;
  }
  norm[i] = '\0';

  if (!strcmp(norm, "fixed")) {
    return BANDIT_A6_OFFPOLICY_FIXED;
  } else if (!strcmp(norm, "ips")) {
    return BANDIT_A6_OFFPOLICY_IPS;
  } else if (!strcmp(norm, "clipped") || !strcmp(norm, "clippedips") ||
             !strcmp(norm, "clipped_ips") || !strcmp(norm, "clipped-ips")) {
    return BANDIT_A6_OFFPOLICY_CLIPPED_IPS;
  }

  return ADARARE_A6_OFFPOLICY_MODE_DEFAULT;

}

static inline const char *bandit_a6_offpolicy_mode_label(u8 mode) {

  switch ((bandit_a6_offpolicy_mode_t)mode) {
    case BANDIT_A6_OFFPOLICY_FIXED: return "fixed";
    case BANDIT_A6_OFFPOLICY_IPS: return "ips";
    case BANDIT_A6_OFFPOLICY_CLIPPED_IPS: return "clipped_ips";
    default: return "clipped_ips";
  }

}

static void bandit_update_arm_model(bandit_state_t *bandit,
                                    bandit_arm_state_t *arm,
                                    const double x[BANDIT_CTX_DIM],
                                    double reward, double eta) {

  if (!bandit || !arm || !x || eta <= 0.0) { return; }

  if (reward < 0.0) reward = 0.0;
  if (reward > 1.0) reward = 1.0;

  for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
    for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
      double v = arm->A[r][c] + eta * x[r] * x[c];
      if (!isfinite(v)) v = 0.0;
      arm->A[r][c] = v;
    }
    double br = arm->b[r] + eta * reward * x[r];
    if (!isfinite(br)) br = 0.0;
    arm->b[r] = br;
  }

  double max_abs_A = 0.0;
  double max_abs_b = 0.0;
  for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
    for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
      double a = fabs(arm->A[r][c]);
      if (a > max_abs_A) max_abs_A = a;
    }
    double b = fabs(arm->b[r]);
    if (b > max_abs_b) max_abs_b = b;
  }

  /* Rescale A only when A is oversized; b alone must not trigger rescaling A. */
  if (max_abs_A > BANDIT_MATRIX_VAL_CAP) {
    double scale = BANDIT_MATRIX_VAL_CAP / max_abs_A;
    if (!isfinite(scale) || scale <= 0.0) scale = 1.0;
    if (scale > 1.0) scale = 1.0;
    if (scale < 1e-12) scale = 1e-12;
    for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
      for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
        arm->A[r][c] *= scale;
      }
      /* Rescale b together with A to keep theta = A^{-1}b in the same scale. */
      arm->b[r] *= scale;
    }
  } else if (max_abs_b > BANDIT_MATRIX_VAL_CAP) {
    /* Keep b bounded without forcing A rescale. */
    double b_scale = BANDIT_MATRIX_VAL_CAP / max_abs_b;
    if (b_scale > 0.0 && b_scale < 1.0 && isfinite(b_scale)) {
      for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
        arm->b[r] *= b_scale;
      }
    }
  }

  for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
    if (arm->A[r][r] < bandit->ridge_lambda) {
      arm->A[r][r] = bandit->ridge_lambda;
    }
    for (int c = r + 1; c < BANDIT_CTX_DIM; ++c) {
      arm->A[c][r] = arm->A[r][c];
    }
  }

}

u32 bandit_dict_prob_for_arm(u32 arm_idx) {
  const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm_idx);
  if (!cfg) { return AFL_BANDIT_DICT_PROB_DEFAULT; }
  if (cfg->dict_prob > 100U) { return 100U; }
  return cfg->dict_prob;
}

/* --- Helper: Robust Normalization --- */

static inline double bandit_log_compress(double val) {
    if (val > 0.0) return log1p(val);
    if (val < 0.0) return -log1p(-val);
    return 0.0;
}

static inline double bandit_normalize_reward(double raw_reward) {
  if (raw_reward < 0.0) return 0.0;
  if (raw_reward > 1.0) return 1.0;
  return raw_reward;
}

static inline double bandit_clamp_feature(double val) {

  if (!isfinite(val) || val < 0.0) return 0.0;
  if (val > BANDIT_X_CAP) return BANDIT_X_CAP;
  return val;

}

const char *bandit_rarity_norm_label(bandit_rarity_norm_t norm) {
  switch (norm) {
    case BANDIT_RARITY_NORM_PATH_LEN: return "path_len";
    case BANDIT_RARITY_NORM_NONE:
    default: return "none";
  }
}

/* --- Core Functions --- */

void bandit_deinit(bandit_state_t *bandit) {
  if (!bandit) { return; }

  if (bandit_dbg_fp) {
    fclose(bandit_dbg_fp);
    bandit_dbg_fp = NULL;
  }
  bandit_dbg_fp_inited = 0;
  
  if (bandit->log_fp) { fclose(bandit->log_fp); }
  if (bandit->log_path) { ck_free(bandit->log_path); }
  if (bandit->verify_fp) { fclose(bandit->verify_fp); }
  if (bandit->verify_log_path) { ck_free(bandit->verify_log_path); }
  if (bandit->score_res) ck_free(bandit->score_res);
  if (bandit->edges_rate_res) ck_free(bandit->edges_rate_res);
  if (bandit->rarity_rate_res) ck_free(bandit->rarity_rate_res);
  if (bandit->cmplog_rate_res) ck_free(bandit->cmplog_rate_res);
  if (bandit->arms) ck_free(bandit->arms);

  struct afl_state *saved_owner = bandit->owner;
  memset(bandit, 0, sizeof(bandit_state_t));
  bandit->owner = saved_owner;
}

void bandit_init(bandit_state_t *bandit, u32 arms, u64 window_ms) {
  if (!bandit) { return; }

  bandit_deinit(bandit);

  bandit->reward_mode = BANDIT_REWARD_NOVELTY;
  bandit->reward_formula = BANDIT_REWARD_RATE_COST;
  bandit->beta = 1.0; 
  bandit->gamma = 1.0;

  if (!arms) { arms = bandit_default_arm_count(); }
  u32 max_arms = bandit_default_arm_count();
  if (arms > max_arms) { arms = max_arms; }

  if (!window_ms) { window_ms = AFL_BANDIT_DEFAULT_WINDOW_MS; }

  bandit->arms = ck_alloc(arms * sizeof(bandit_arm_state_t));
  if (!bandit->arms) { return; } 
  
  memset(bandit->arms, 0, arms * sizeof(bandit_arm_state_t));

  bandit->enabled = 1;
  bandit->num_arms = arms;
  bandit->current_arm = 0;
  bandit->current_arm_eff = 0;
  bandit->dwell_windows = 0;
  bandit->last_selected_arm = 0;
  bandit->rng_state = 0;
  bandit->verify_enabled =
      bandit_env_int("AFL_ADARARE_VERIFY", 0, 0, 1) ? 1 : 0;
  bandit->rng_seeded_from_owner = 0;
  bandit->rng_log_idx = 0;
  bandit->window_ms = window_ms;
  bandit->last_cur_window_ms = window_ms;
  
  /* Initial Start Time */
  bandit->win_start_time = bandit_now_ms();
  bandit->win_last_ts = bandit->win_start_time;
  bandit->win_last_arm = bandit->current_arm;
  bandit->win_clamp_hi = 0;
  bandit->win_guard_hits = 0;
  bandit->win_trend_active = 0;
  bandit->win_reward_zero = 0;
  bandit->win_has_progress = 0;
  bandit->win_cmplog_progress = 0.0;
  bandit->win_cmplog_inject_count = 0;
  bandit->win_cmplog_inject_sum = 0.0;
  bandit->win_cmplog_inject_clipped_count = 0;
  
  bandit->total_rounds = 0.0;     
  bandit->total_selections = 0;   
  
  bandit->last_win_gate = 1.0;
  bandit->last_win_gate_execavg = 1.0;
  bandit->last_raw_reward = 0.0;
  bandit->last_raw_reward_pre_cap = 0.0;
  bandit->last_gate_factor = 1.0;
  bandit->last_gate_bonus = 0.0;
  bandit->last_gate_bonus_final = 0.0;
  bandit->last_gate_bonus_eff = 0.0;
  bandit->last_gate_bonus_headroom = 0.0;
  bandit->last_gate_bonus_inject = 0.0;
  bandit->last_gate_progress_gated = 0;
  bandit->last_zero_prog_pen = 0.0;
  bandit->last_win_clamp_hi = 0;
  bandit->last_win_guard_hits = 0;
  bandit->last_win_trend_active = 0;
  bandit->last_win_reward_zero = 0;
  bandit->last_win_has_progress = 0;
  bandit->last_stag_bonus_boost = 0;
  bandit->last_dwell_blocked = 0;
  bandit->last_dwell_emergency_zero = 0;
  bandit->last_guard_penalty = 1.0;
  bandit->last_guard_streak = 0;
  bandit->last_guard_arm = 0;
  bandit->last_zp_streak = 0;
  bandit->last_zp_applied = 0;
  bandit->last_zp_factor = 1.0;
  bandit->last_a6_eta_eff = 0.0;
  bandit->last_a6_eta_stats = 0.0;
  bandit->last_a6_eta_model = 0.0;
  bandit->last_a6_pi_eff = 0.0;
  bandit->last_a6_ips_w = 1.0;
  bandit->last_a6_eff_arm = BANDIT_ARM_A6;
  bandit->last_mix_p_used = 0.5;
  bandit->last_mix_p_next = 0.5;
  bandit->a6_sub_progress_ema = 0.0;
  bandit->a6_sub_samples = 0;
  
  bandit->rarity_norm = BANDIT_RARITY_NORM_PATH_LEN;
  bandit->discount =
      bandit_env_double("AFL_ADARARE_DISCOUNT", 0.999, 0.90, 1.0);
  bandit->warmup_windows = 20; 
  bandit->warmup_pulls_target = bandit_env_double(
      "AFL_ADARARE_WARMUP_PULLS", BANDIT_WARMUP_PULLS_PER_ARM, 0.0, 1000.0);
  bandit->last_warmup_min_pulls = 0.0;
  bandit->in_warmup = 1;
  bandit->mix_choice = 0;
  bandit->last_mix_choice = 0;
  bandit->last_arm_used = 0;
  bandit->last_arm_eff_used = 0;
  bandit->alpha = 0.6;
  bandit->use_contextual = 1;
  bandit->ridge_lambda =
      bandit_env_double("AFL_ADARARE_RIDGE", BANDIT_LINUCB_RIDGE, 1.0, 1000.0);
  bandit->gate_multiplier =
      bandit_env_double("AFL_ADARARE_GATE_MULT", 0.02, 0.0, 1.0);
  bandit->gate_cap =
      bandit_env_double("AFL_ADARARE_GATE_CAP", BANDIT_GATE_CAP, 1.0, 10.0);
  bandit->revisit_time_ms = bandit_env_u64(
      "AFL_ADARARE_REVISIT_MS", BANDIT_REVISIT_COOLDOWN_MS, 30ULL * 1000ULL,
      24ULL * 60ULL * 60ULL * 1000ULL);
  bandit->last_improve_ms = bandit->win_start_time;
  bandit->last_revisit_ms = 0;
  bandit->stagnation_windows = 0;
  bandit->last_dyn_stag_thresh = BANDIT_STAG_WINDOWS;
  bandit->stag_ema_reward = 0.0;
  bandit->stag_ema_edges = 0.0;
  bandit->stag_slope_reward = 0.0;
  bandit->stag_slope_edges = 0.0;
  bandit->stag_trend_inited = 0;
  bandit->stag_trend_active = 0;
  bandit->x_ema_inited = 0;
  bandit->rarity_decay = bandit_env_double("AFL_ADARARE_SCORE_DECAY",
                                           BANDIT_DEFAULT_RARITY_DECAY, 0.90,
                                           1.0);
  bandit->rarity_ema =
      bandit_env_double("AFL_ADARARE_RARITY_EMA", 1.0, 0.05, 1.0);
  bandit->mix_p = bandit_env_double("AFL_ADARARE_MIX_P", 0.5, 0.0, 1.0);
  bandit->a6_offpolicy_mode = (bandit_a6_offpolicy_mode_t)bandit_parse_a6_offpolicy_mode();
  if (bandit->mix_p < ADARARE_MIX_P_MIN) bandit->mix_p = ADARARE_MIX_P_MIN;
  if (bandit->mix_p > ADARARE_MIX_P_MAX) bandit->mix_p = ADARARE_MIX_P_MAX;
  bandit->last_mix_p_used = bandit->mix_p;
  bandit->last_mix_p_next = bandit->mix_p;
  for (u32 k = 0; k < AFL_BANDIT_MAX_ARMS; ++k) {
    bandit->a6_topk[k] = 0;
    bandit->a6_topk_prob[k] = 0.0;
  }
  bandit->last_a6_choice = 0;
  bandit->a6_choice_pi = 0.0;
  bandit->last_a6_pi_floor = 0.0;
  bandit->a6_to_a1 = 0;
  bandit->a6_to_a2 = 0;
  bandit->a6_q1 = 0.0;
  bandit->a6_q2 = 0.0;
  bandit->tie_break_hits_total = 0;
  bandit->tie_break_hits_win = 0;
  bandit->tie_break_det_hits_total = 0;
  bandit->tie_break_det_hits_win = 0;
  bandit->last_tie_break_det = 0;
  bandit->last_tie_eps = 0.0;
  bandit->dict_baseline_prob =
      (u32)bandit_env_u64("AFL_ADARARE_DICT_BASELINE_PROB", 100, 0, 100);
  bandit->dict_enable =
      bandit_env_int("AFL_ADARARE_DICT_ENABLE", 1, 0, 1) ? 1 : 0;
  bandit->reward_alpha =
      bandit_env_double("AFL_ADARARE_REWARD_ALPHA", 0.75, 0.0, 1.0);
  bandit->reward_beta =
      bandit_env_double("AFL_ADARARE_REWARD_BETA", 0.20, 0.0, 1.0);
  bandit->reward_gamma =
      bandit_env_double("AFL_ADARARE_REWARD_GAMMA", 0.05, 0.0, 1.0);
  bandit->reward_delta =
      bandit_env_double("AFL_ADARARE_REWARD_DELTA", 0.35, 0.0, 10.0);
      
  bandit->reward_c1 =
      bandit_env_double("AFL_ADARARE_REWARD_C1", 50.0, 1e-12, 1e12);
  bandit->reward_c2 =
      bandit_env_double("AFL_ADARARE_REWARD_C2", 5.0, 1e-12, 1e12);
  bandit->reward_c3 =
      bandit_env_double("AFL_ADARARE_REWARD_C3", 10.0, 1e-9, 1e18);
  bandit->cmp_reward =
      bandit_env_int("AFL_ADARARE_CMP_REWARD", 1, 0, 1) ? 1 : 0;
  bandit->cmp_producer_mode =
      (u8)bandit_env_int("AFL_ADARARE_CMP_PRODUCER_MODE", 2, 0, 2);
  bandit->cmp_a3_boost =
      bandit_env_int("AFL_ADARARE_CMP_A3_BOOST", 1, 0, 1) ? 1 : 0;
  bandit->cmp_min_gain =
      bandit_env_double("AFL_ADARARE_CMP_MIN_GAIN", 0.25, 0.0, 1e9);
  bandit->cmp_win_clip =
      bandit_env_double("AFL_ADARARE_CMP_WIN_CLIP", 8.0, 0.0, 1e18);
  bandit->cmp_one_shot_site =
      bandit_env_int("AFL_ADARARE_CMP_ONE_SHOT_SITE", 0, 0, 1) ? 1 : 0;
  bandit->cmp_rarity_lambda =
      bandit_env_double("AFL_ADARARE_CMP_RARITY_LAMBDA", 0.0, 0.0, 10.0);
  bandit->cmp_baseline_norm =
      bandit_env_int("AFL_ADARARE_CMP_BASELINE_NORM", 0, 0, 1) ? 1 : 0;
  bandit->cmp_baseline_ema =
      bandit_env_double("AFL_ADARARE_CMP_BASELINE_EMA", 0.20, 0.0, 1.0);
      
  double wsum = bandit->reward_alpha + bandit->reward_beta + bandit->reward_gamma;
  if (wsum <= 0.0) {
    bandit->reward_alpha = 0.75;
    bandit->reward_beta = 0.20;
    bandit->reward_gamma = 0.05;
  }
  bandit->alpha =
      bandit_env_double("AFL_ADARARE_ALPHA", 0.6, 0.0, 10.0);
  bandit->use_contextual =
      bandit_env_int("AFL_ADARARE_CONTEXTUAL", 1, 0, 1) ? 1 : 0;
      
  bandit->last_p90_score = 1.0;
  bandit->last_p90_n = 0;
  bandit->last_p90_valid = 0;
  bandit->last_p90_add_edges = 0;
  bandit->last_p90_add_rarity = 0;
  bandit->thrpt_ref_ema = 0.0;
  bandit->thrpt_ref_inited = 0;
  bandit->log_fp = NULL;
  bandit->log_path = NULL;
  bandit->log_header_written = 0;
  bandit->config_written = 0;
  bandit->last_dict_prob = bandit_current_dict_prob(bandit);
  
  bandit->rng_state =
      get_cur_time_us() ^ (u64)getpid() ^ (u64)(uintptr_t)bandit;
  if (!bandit->rng_state) bandit->rng_state = 1;
  bandit->verify_log_path = NULL;
  bandit->verify_fp = NULL;
  
  bandit->last_thrpt = 0.0;
  bandit->last_thrpt_ref = 0.0;
  bandit->last_thrpt_pen = 0.0;
  bandit->last_thrpt_pen_eff = 0.0;
  bandit->last_timeout_hz = 0.0;
  bandit->last_slow_hz = 0.0;
  bandit->last_delta_bits = 0.0;
  bandit->last_delta_rarity = 0.0;
  bandit->last_dict_attempts = 0;
  bandit->last_dict_taken = 0;
  
  bandit->last_win_new_bits = 0;
  bandit->last_win_rarity_mass = 0.0;
  bandit->last_win_timeouts = 0;
  bandit->last_win_slow_execs = 0;
  bandit->last_win_novelty = 0.0;
  bandit->last_time_sec = 1.0;
  bandit->last_edges_rate = 0.0;
  bandit->last_rarity_rate = 0.0;
  bandit->last_cmplog_rate = 0.0;
  bandit->last_cmplog_term = 0.0;
  bandit->last_cmplog_mod = 0.0;
  bandit->last_cmplog_rate_norm = 0.0;
  bandit->cmplog_rate_ema = 0.0;
  bandit->last_cmplog_inject_count = 0;
  bandit->last_cmplog_inject_sum = 0.0;
  bandit->last_cmplog_inject_clipped_count = 0;
  bandit->last_scale_c3_used =
      (isfinite(bandit->reward_c3) && bandit->reward_c3 > 0.0)
          ? bandit->reward_c3
          : 10.0;
  bandit->last_p90_cmplog = 0.0;
  bandit->last_reward_delta_used =
      (isfinite(bandit->reward_delta) && bandit->reward_delta > 0.0)
          ? bandit->reward_delta
          : 0.35;
  bandit->last_edges_per_exec = 0.0;
  bandit->last_rarity_per_exec = 0.0;
  bandit->last_edges_term = 0.0;
  bandit->last_rarity_term = 0.0;
  
  bandit->linucb_invert_fail_last = 0;
  bandit->linucb_rad_cap_hits_last = 0;
  bandit->linucb_score_cap_hits_last = 0;

#if BANDIT_BUILD_ID_AUDIT
  if (!bandit_build_id_logged) {
    const char *build_id = adarare_build_id_effective();
    fprintf(stderr,
            "[adarare] build_id=%s warmup_pulls=%.3f progress_gate=1 "
            "gate_headroom=1 tie_break=deterministic tie_eps_rel=%.6f "
            "cmp_reward=%u cmp_mode=%u a3_cmp_boost=%u delta=%.3f c3=%.3f "
            "cmp_baseline_norm=%u cmp_baseline_ema=%.3f\n",
            build_id, bandit->warmup_pulls_target, ADARARE_TIE_EPS_REL,
            (unsigned int)bandit->cmp_reward,
            (unsigned int)bandit->cmp_producer_mode,
            (unsigned int)bandit->cmp_a3_boost, bandit->reward_delta,
            bandit->reward_c3, (unsigned int)bandit->cmp_baseline_norm,
            bandit->cmp_baseline_ema);
    bandit_build_id_logged = 1;
  }
#endif

  for (u32 i = 0; i < bandit->num_arms; ++i) {
    for (u32 r = 0; r < BANDIT_CTX_DIM; ++r) {
      for (u32 c = 0; c < BANDIT_CTX_DIM; ++c) {
        bandit->arms[i].A[r][c] = (r == c) ? bandit->ridge_lambda : 0.0;
      }
      bandit->arms[i].b[r] = 0.0;
    }
    bandit->arms[i].last_selected_ms = 0;
    bandit->arms[i].last_thrpt = 0.0;
    bandit->arms[i].last_seen_ms = 0;
    bandit->arms[i].warmup_pulls = 0.0;
    bandit->arms[i].guard_streak = 0;
    bandit->arms[i].zp_streak = 0;
    bandit->arms[i].edges_ema = 0.0;
    bandit->arms[i].early_edges_ema = 0.0;
    bandit->arms[i].edges_per_exec_ema = 0.0;
    bandit->arms[i].rarity_per_exec_ema = 0.0;
  }
  for (u32 k = 0; k < BANDIT_CTX_DIM; ++k) {
    bandit->last_raw_x[k] = 0.0;
    bandit->last_x[k] = 0.0;
  }
  
  bandit->score_res = ck_alloc(sizeof(bandit_reservoir_t));
  bandit->edges_rate_res = ck_alloc(arms * sizeof(bandit_reservoir_t));
  bandit->rarity_rate_res = ck_alloc(arms * sizeof(bandit_reservoir_t));
  bandit->cmplog_rate_res = ck_alloc(arms * sizeof(bandit_reservoir_t));
  
  if (!bandit->score_res || !bandit->edges_rate_res || !bandit->rarity_rate_res ||
      !bandit->cmplog_rate_res) {
      bandit_deinit(bandit);
      return; 
  }

  reservoir_reset((bandit_reservoir_t*)bandit->score_res);
  for (u32 i = 0; i < arms; ++i) {
    reservoir_reset(&((bandit_reservoir_t *)bandit->edges_rate_res)[i]);
    reservoir_reset(&((bandit_reservoir_t *)bandit->rarity_rate_res)[i]);
    reservoir_reset(&((bandit_reservoir_t *)bandit->cmplog_rate_res)[i]);
  }

  bandit_build_a6_topk(bandit);
}

static void bandit_apply_arm_policy(afl_state_t *afl, bandit_state_t *bandit) {

  if (!bandit) { return; }

  u32 arm = bandit->current_arm_eff;
  if (arm >= bandit->num_arms) {
    arm = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  }
  if (arm >= bandit->num_arms) { arm = 0; }

  const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm);
  u32 dict_prob = bandit->dict_baseline_prob;
  if (bandit->dict_enable) {
    dict_prob = bandit_dict_prob_for_arm(arm);
  }

  bandit->last_dict_prob = dict_prob;
  if (!afl) { return; }

  afl->adarare_dict_prob = dict_prob;

  if (!cfg) {
    afl->adarare_prefer_favored = 0;
    afl->adarare_prefer_new = 0;
    afl->adarare_havoc_mul_pct = 100;
    return;
  }

  afl->adarare_prefer_favored = cfg->prefer_favored;
  afl->adarare_prefer_new = cfg->prefer_new ? 1 : 0;

  double mul = cfg->havoc_stack_mul;
  if (!isfinite(mul) || mul <= 0.0) mul = 1.0;
  double pct_d = mul * 100.0;
  if (!isfinite(pct_d) || pct_d < 10.0) pct_d = 10.0;
  if (pct_d > 400.0) pct_d = 400.0;
  afl->adarare_havoc_mul_pct = (u32)(pct_d + 0.5);

  if (cfg->trim_policy == 1) {
    afl->disable_trim = 1;
  } else if (cfg->trim_policy == 2) {
    afl->disable_trim = 0;
  }

}

void bandit_set_owner(bandit_state_t *bandit, struct afl_state *afl) {
  if (!bandit) return;
  bandit->owner = afl;
  if (afl) {
    afl->bandit_dict_enable = bandit->dict_enable ? 1 : 0;
    bandit_apply_arm_policy(afl, bandit);
    if (!bandit->rng_seeded_from_owner) {
      bandit->rng_state =
          ((u64)afl->rand_seed[0] << 32) ^ (u64)afl->rand_seed[1] ^
          0xAF1BABD190ULL ^ (u64)(uintptr_t)bandit;
      if (!bandit->rng_state) bandit->rng_state = 1;
      bandit->rng_seeded_from_owner = 1;
    }
  }
}

/* Event Hooks */
void bandit_on_new_cov(bandit_state_t *bandit, u64 new_bits, double novelty_delta, double gate) {
  if (!bandit || !bandit->enabled) return;
  if (!bandit->win_start_time) bandit->win_start_time = bandit_now_ms();
  bandit->win_new_cov += 1;
  bandit->win_new_bits += new_bits;
  bandit->win_novelty += novelty_delta;
  u64 samples = new_bits ? new_bits : 1;
  bandit->win_gate_sum += gate * (double)samples;
  bandit->win_gate_samples += samples;
}

void bandit_on_rarity_mass(bandit_state_t *bandit, double rarity_mass, u64 path_len) {
  if (!bandit || !bandit->enabled) return;
  if (!bandit->win_start_time) bandit->win_start_time = bandit_now_ms();
  double value = rarity_mass;
  if (bandit->rarity_norm == BANDIT_RARITY_NORM_PATH_LEN) {
    double denom = (double)(path_len ? path_len : 1);
    value = rarity_mass / denom;
  }
  bandit->win_rarity_mass += value;
  bandit->win_rarity_samples += 1;
  bandit->win_path_len_sum += path_len;
}

void bandit_on_exec_gate(bandit_state_t *bandit, double gate) {
  if (!bandit || !bandit->enabled) return;
  bandit->win_gate_exec_sum += gate;
  bandit->win_gate_exec_samples += 1;
}

void bandit_on_exec(bandit_state_t *bandit, u64 execs, u64 time_us, u64 timeouts, u64 slow_execs) {
  if (!bandit || !bandit->enabled) return;
  if (!bandit->win_start_time) bandit->win_start_time = bandit_now_ms();
  bandit->win_execs += execs;
  bandit->win_time_us += time_us;
  bandit->win_timeouts += timeouts;
  bandit->win_slow_execs += slow_execs;
}

void bandit_on_cmplog_progress(bandit_state_t *bandit, double progress_delta) {
  /* Producer-agnostic hook: external cmp-log / branch-distance sources feed
     continuous progress here; scheduler logic intentionally stays local. */
  if (!bandit || !bandit->enabled) return;
  if (!bandit->cmp_reward) return;
  if (!isfinite(progress_delta) || progress_delta <= 0.0) return;
  if (!bandit->win_start_time) bandit->win_start_time = bandit_now_ms();

  double cur = bandit->win_cmplog_progress;
  if (!isfinite(cur) || cur < 0.0) cur = 0.0;
  double clip = bandit->cmp_win_clip;
  if (!isfinite(clip) || clip < 0.0) clip = 8.0;
  double added = progress_delta;
  u8 clipped = 0;
  if (clip > 0.0) {
    if (cur >= clip) {
      added = 0.0;
      clipped = 1;
    } else if (cur + added > clip) {
      added = clip - cur;
      if (added < 0.0) added = 0.0;
      clipped = 1;
    }
  }

  double next = cur + added;
  if (!isfinite(next) || next < 0.0 ||
      (clip > 0.0 && (next < cur || next > clip + 1e-12))) {
    bandit->win_cmplog_progress = cur;
    return;
  }
  bandit->win_cmplog_progress = next;

  if (bandit->win_cmplog_inject_count < ULLONG_MAX) {
    bandit->win_cmplog_inject_count++;
  }
  double inject_sum = bandit->win_cmplog_inject_sum;
  if (!isfinite(inject_sum) || inject_sum < 0.0) inject_sum = 0.0;
  double inject_next = inject_sum + added;
  if (isfinite(inject_next) && inject_next >= 0.0) {
    bandit->win_cmplog_inject_sum = inject_next;
  } else {
    bandit->win_cmplog_inject_sum = inject_sum;
  }
  if (clipped && bandit->win_cmplog_inject_clipped_count < ULLONG_MAX) {
    bandit->win_cmplog_inject_clipped_count++;
  }
}

double bandit_current_multiplier(const bandit_state_t *bandit) {
  if (!bandit || !bandit->enabled) { return 1.0; }
  u32 arm = bandit->current_arm_eff;
  if (arm >= bandit->num_arms) {
    arm = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  }
  return bandit_multiplier_for_arm(arm);
}

u8 bandit_maybe_rotate(bandit_state_t *bandit) {

  if (!bandit || !bandit->enabled || !bandit->arms || !bandit->window_ms) {
    return 0;
  }

  /* P0: Capture Entry Time. */
  u64 entry_now_us = get_cur_time_us();
  u64 entry_now_ms = entry_now_us / 1000;
  
  /* Audit Hardening: Protection against backward time jumps */
  if (bandit->win_start_time > entry_now_ms) {
    bandit->win_start_time = entry_now_ms;
  }
  if (!bandit->win_start_time) { bandit->win_start_time = entry_now_ms; }
  if (!bandit->win_last_ts || bandit->win_last_ts < bandit->win_start_time ||
      bandit->win_last_ts > entry_now_ms) {
    bandit->win_last_ts = bandit->win_start_time;
    bandit->win_last_arm = bandit->current_arm;
  }

  u64 cur_window_ms = bandit_current_window_ms(bandit);
  bandit->last_cur_window_ms = cur_window_ms;
  if (entry_now_ms - bandit->win_start_time < cur_window_ms) { return 0; }
  
  u32 prev_arm_idx = bandit->current_arm;

  u64 old_start_ms = bandit->win_start_time;
  u64 rotate_start_us = entry_now_us;

  u64 win_id = bandit->rotate_count + 1;

  bandit_arm_state_t *current = &bandit->arms[bandit->current_arm];
  u32 window_arm_eff = bandit->current_arm_eff;
  if (window_arm_eff >= bandit->num_arms) {
    window_arm_eff = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  }
  bandit->current_arm_eff = window_arm_eff;
  bandit_win_account(bandit, entry_now_ms);
  
  bandit->in_warmup = bandit_in_pulls_warmup(bandit);
  bandit->last_warmup_min_pulls = bandit_min_warmup_pulls(bandit);

  /* ============================================================ */
  /* 1. Time & Rate Calculation                                   */
  /* ============================================================ */
  
  double time_sec;
  if (bandit->win_time_us > 0) {
    time_sec = (double)bandit->win_time_us / 1000000.0;
  } else {
    u64 dur = (entry_now_ms >= bandit->win_start_time) ? (entry_now_ms - bandit->win_start_time) : 0;
    time_sec = (double)dur / 1000.0;
  }
  
  double win_sec_fallback = (double)cur_window_ms / 1000.0;
  if (win_sec_fallback < 1e-4) win_sec_fallback = 1e-4;
  double safe_time = (time_sec > 1e-6) ? time_sec : win_sec_fallback;

  double base_raw = 0.0;
  switch (bandit->reward_mode) {
      case BANDIT_REWARD_BITS:
          base_raw = (double)bandit->win_new_bits / safe_time;
          break;
      case BANDIT_REWARD_NOVELTY:
          base_raw = bandit->win_novelty / safe_time;
          break;
      case BANDIT_REWARD_RARITY_MASS:
          base_raw = bandit->win_rarity_mass / safe_time;
          break;
      case BANDIT_REWARD_EVENT:
      default:
          base_raw = (double)bandit->win_new_cov / safe_time;
          break;
  }

  if (!isfinite(base_raw)) base_raw = 0.0;
  bandit->last_base_raw = base_raw;

  /* ============================================================ */
  /* 2. Gate Bonus (Applied on final reward only)                 */
  /* ============================================================ */
  
  double avg_gate = 0.0;
  if (bandit->win_gate_exec_samples > 0) {
      avg_gate = bandit->win_gate_exec_sum / bandit->win_gate_exec_samples;
  } else if (bandit->win_gate_samples > 0) {
      avg_gate = bandit->win_gate_sum / bandit->win_gate_samples;
  }

  double gate_bonus = 0.0;
  double gate_factor = 1.0;
  if (avg_gate > 0.0) {
      gate_bonus = bandit_log_compress(avg_gate) * bandit->gate_multiplier;
      double gate_bonus_cap = bandit->gate_cap - 1.0;
      if (gate_bonus_cap < 0.0) gate_bonus_cap = 0.0;
      if (!isfinite(gate_bonus) || gate_bonus < 0.0) gate_bonus = 0.0;
      if (gate_bonus > gate_bonus_cap) gate_bonus = gate_bonus_cap;
      gate_factor = 1.0 + gate_bonus;
  }
  
  /* ============================================================ */
  /* 3. Paper Reward: Adaptive Rate-based                         */
  /* ============================================================ */
  double thrpt = (double)bandit->win_execs / safe_time;
  
  if (!bandit->thrpt_ref_inited) {
    bandit->thrpt_ref_ema = thrpt;
    bandit->thrpt_ref_inited = 1;
  } else if (bandit->in_warmup) {
    bandit->thrpt_ref_ema = 0.9 * bandit->thrpt_ref_ema + 0.1 * thrpt;
  } else {
    if (thrpt > bandit->thrpt_ref_ema) {
         bandit->thrpt_ref_ema = 0.9 * bandit->thrpt_ref_ema + 0.1 * thrpt;
    } else {
         bandit->thrpt_ref_ema = 0.999 * bandit->thrpt_ref_ema + 0.001 * thrpt;
    }
  }

  double thrpt_pen = 0.0;
  if (bandit->thrpt_ref_ema > 0.0) {
    thrpt_pen = (bandit->thrpt_ref_ema - thrpt) / bandit->thrpt_ref_ema;
    if (thrpt_pen < 0.0) thrpt_pen = 0.0;
  }

  double delta_bits = (double)bandit->win_new_bits;
  double delta_rarity = bandit->win_rarity_mass;
  double exec_denom = (double)(bandit->win_execs ? bandit->win_execs : 1);
  double edges_per_exec = delta_bits / exec_denom;
  double rarity_per_exec = delta_rarity / exec_denom;
  if (!isfinite(edges_per_exec) || edges_per_exec < 0.0) edges_per_exec = 0.0;
  if (!isfinite(rarity_per_exec) || rarity_per_exec < 0.0) {
    rarity_per_exec = 0.0;
  }

  double edges_rate = delta_bits / safe_time;
  double rarity_rate = delta_rarity / safe_time;
  double cmplog_progress = bandit->win_cmplog_progress;
  if (!isfinite(cmplog_progress) || cmplog_progress < 0.0) {
    cmplog_progress = 0.0;
  }
  double cmplog_rate = cmplog_progress / safe_time;
  if (!isfinite(edges_rate) || edges_rate < 0.0) edges_rate = 0.0;
  if (!isfinite(rarity_rate) || rarity_rate < 0.0) rarity_rate = 0.0;
  if (!isfinite(cmplog_rate) || cmplog_rate < 0.0) cmplog_rate = 0.0;
  double cmp_baseline_ema = bandit->cmp_baseline_ema;
  if (!isfinite(cmp_baseline_ema) || cmp_baseline_ema < 0.0 ||
      cmp_baseline_ema > 1.0) {
    cmp_baseline_ema = 0.20;
  }
  double cmplog_rate_ema = bandit->cmplog_rate_ema;
  if (!isfinite(cmplog_rate_ema) || cmplog_rate_ema < 0.0) {
    cmplog_rate_ema = 0.0;
  }
  if (isfinite(cmplog_rate) && cmplog_rate >= 0.0) {
    if (cmplog_rate_ema <= 0.0) {
      cmplog_rate_ema = cmplog_rate;
    } else {
      cmplog_rate_ema =
          (1.0 - cmp_baseline_ema) * cmplog_rate_ema + cmp_baseline_ema * cmplog_rate;
    }
  }
  if (!isfinite(cmplog_rate_ema) || cmplog_rate_ema < 0.0) cmplog_rate_ema = 0.0;
  bandit->cmplog_rate_ema = cmplog_rate_ema;

  u32 r1 = bandit_get_random(bandit);
  u32 r2 = bandit_get_random(bandit);
  u32 r3 = bandit_get_random(bandit);
  u32 r4 = bandit_get_random(bandit);
  u32 r5 = bandit_get_random(bandit);
  u32 r6 = bandit_get_random(bandit);
  u8 p90_add_edges = 0;
  u8 p90_add_rarity = 0;

  u32 res_arm = window_arm_eff;
  if (res_arm >= bandit->num_arms) {
    res_arm = bandit->current_arm;
    if (res_arm >= bandit->num_arms) res_arm = 0;
  }
  bandit_reservoir_t *edges_res_arr =
      (bandit_reservoir_t *)bandit->edges_rate_res;
  bandit_reservoir_t *rarity_res_arr =
      (bandit_reservoir_t *)bandit->rarity_rate_res;
  bandit_reservoir_t *cmplog_res_arr =
      (bandit_reservoir_t *)bandit->cmplog_rate_res;
  bandit_reservoir_t *edges_res = &edges_res_arr[res_arm];
  bandit_reservoir_t *rarity_res = &rarity_res_arr[res_arm];
  bandit_reservoir_t *cmplog_res =
      cmplog_res_arr ? &cmplog_res_arr[res_arm] : NULL;

  if (isfinite(edges_rate) && edges_rate > ADARARE_P90_SIGNAL_EPS) {
    reservoir_add(edges_res, edges_rate, r1, r2);
    p90_add_edges = 1;
  }
  if (isfinite(rarity_rate) && rarity_rate > ADARARE_P90_SIGNAL_EPS) {
    reservoir_add(rarity_res, rarity_rate, r3, r4);
    p90_add_rarity = 1;
  }
  if (cmplog_res && isfinite(cmplog_rate) && cmplog_rate > ADARARE_P90_SIGNAL_EPS) {
    reservoir_add(cmplog_res, cmplog_rate, r5, r6);
  }

  double p90_edges = reservoir_p90(edges_res);
  double p90_rarity = reservoir_p90(rarity_res);
  double p90_cmplog = reservoir_p90(cmplog_res);
  if (!isfinite(p90_edges) || p90_edges < 0.0) p90_edges = 0.0;
  if (!isfinite(p90_rarity) || p90_rarity < 0.0) p90_rarity = 0.0;
  if (!isfinite(p90_cmplog) || p90_cmplog < 0.0) p90_cmplog = 0.0;

  double scale_c1 = bandit->reward_c1;
  double scale_c2 = bandit->reward_c2;
  double scale_c3 = bandit->reward_c3;
  if (!isfinite(scale_c1) || scale_c1 <= 0.0) scale_c1 = 50.0;
  if (!isfinite(scale_c2) || scale_c2 <= 0.0) scale_c2 = 5.0;
  if (!isfinite(scale_c3) || scale_c3 <= 0.0) scale_c3 = 10.0;

  if (!bandit->in_warmup && edges_res->count >= BANDIT_P90_MIN_SAMPLES &&
      p90_edges > 1e-6) {
    scale_c1 = p90_edges;
  }
  if (!bandit->in_warmup && rarity_res->count >= BANDIT_P90_MIN_SAMPLES &&
      p90_rarity > 1e-6) {
    scale_c2 = p90_rarity;
  }
  if (cmplog_res && !bandit->in_warmup &&
      cmplog_res->count >= BANDIT_P90_MIN_SAMPLES && p90_cmplog > 1e-6) {
    scale_c3 = p90_cmplog;
  }

  if (!isfinite(scale_c1) || scale_c1 <= 0.0) scale_c1 = 50.0;
  if (!isfinite(scale_c2) || scale_c2 <= 0.0) scale_c2 = 5.0;
  if (!isfinite(scale_c3) || scale_c3 <= 0.0) scale_c3 = 10.0;

  /* tanh keeps heterogeneous rate signals bounded to [0,1], so one noisy
     channel cannot dominate window reward. */
  double edges_term = tanh(edges_rate / scale_c1);
  double rarity_term = tanh(rarity_rate / scale_c2);
  double cmplog_rate_norm = cmplog_rate / scale_c3;
  if (!isfinite(cmplog_rate_norm) || cmplog_rate_norm < 0.0) {
    cmplog_rate_norm = 0.0;
  }
  if (bandit->cmp_baseline_norm) {
    double cmplog_norm_den = scale_c3;
    if (isfinite(cmplog_rate_ema) && cmplog_rate_ema > cmplog_norm_den) {
      cmplog_norm_den = cmplog_rate_ema;
    }
    if (!isfinite(cmplog_norm_den) || cmplog_norm_den < 1e-9) {
      cmplog_norm_den = 1e-9;
    }
    cmplog_rate_norm = cmplog_rate / cmplog_norm_den;
    if (!isfinite(cmplog_rate_norm) || cmplog_rate_norm < 0.0) {
      cmplog_rate_norm = 0.0;
    }
  }
  double cmplog_term = tanh(cmplog_rate_norm);
  if (!isfinite(edges_term) || edges_term < 0.0) edges_term = 0.0;
  if (!isfinite(rarity_term) || rarity_term < 0.0) rarity_term = 0.0;
  if (!isfinite(cmplog_term) || cmplog_term < 0.0) cmplog_term = 0.0;
  if (cmplog_term > 1.0) cmplog_term = 1.0;
  double cmp_rarity_lambda = bandit->cmp_rarity_lambda;
  if (!isfinite(cmp_rarity_lambda) || cmp_rarity_lambda < 0.0) {
    cmp_rarity_lambda = 0.0;
  }
  double cmplog_mod = cmplog_term * (1.0 + cmp_rarity_lambda * rarity_term);
  if (!isfinite(cmplog_mod)) cmplog_mod = cmplog_term;
  if (cmplog_mod < 0.0) cmplog_mod = 0.0;
  if (cmplog_mod > 1.0) cmplog_mod = 1.0;
  double cmplog_term_used =
      (cmp_rarity_lambda > 0.0) ? cmplog_mod : cmplog_term;
  const bandit_arm_cfg_t *reward_cfg = bandit_arm_cfg_for_arm(window_arm_eff);
  double rw_alpha = bandit->reward_alpha;
  double rw_beta = bandit->reward_beta;
  double rw_gamma = bandit->reward_gamma;
  double rw_delta = bandit->reward_delta;
  double zp_penalty_mul = 1.0;
  if (!isfinite(rw_delta) || rw_delta <= 0.0) rw_delta = 0.35;
  if (reward_cfg) {
    rw_alpha = reward_cfg->w_alpha;
    rw_beta = reward_cfg->w_beta;
    rw_gamma = reward_cfg->w_gamma;
    if (isfinite(reward_cfg->w_delta) && reward_cfg->w_delta > 0.0 &&
        (window_arm_eff != BANDIT_ARM_A3 || bandit->cmp_a3_boost)) {
      rw_delta = reward_cfg->w_delta;
    }
    if (isfinite(reward_cfg->zp_penalty_mul) && reward_cfg->zp_penalty_mul > 0.0) {
      zp_penalty_mul = reward_cfg->zp_penalty_mul;
    }
  }
  if (!isfinite(rw_alpha) || rw_alpha < 0.0) rw_alpha = 0.0;
  if (!isfinite(rw_beta) || rw_beta < 0.0) rw_beta = 0.0;
  if (!isfinite(rw_gamma) || rw_gamma < 0.0) rw_gamma = 0.0;
  if (!isfinite(rw_delta) || rw_delta <= 0.0) rw_delta = 0.35;

  double rw_sum = rw_alpha + rw_beta + rw_gamma + rw_delta;
  if (!isfinite(rw_sum) || rw_sum <= BANDIT_PULLS_EPSILON) {
    rw_alpha = bandit->reward_alpha;
    rw_beta = bandit->reward_beta;
    rw_gamma = bandit->reward_gamma;
    rw_delta = bandit->reward_delta;
    if (!isfinite(rw_alpha) || rw_alpha < 0.0) rw_alpha = 0.75;
    if (!isfinite(rw_beta) || rw_beta < 0.0) rw_beta = 0.20;
    if (!isfinite(rw_gamma) || rw_gamma < 0.0) rw_gamma = 0.05;
    if (!isfinite(rw_delta) || rw_delta <= 0.0) rw_delta = 0.35;
    rw_sum = rw_alpha + rw_beta + rw_gamma + rw_delta;
  }
  if (!isfinite(rw_sum) || rw_sum <= BANDIT_PULLS_EPSILON) {
    rw_alpha = 0.75;
    rw_beta = 0.20;
    rw_gamma = 0.05;
    rw_delta = 0.35;
    rw_sum = rw_alpha + rw_beta + rw_gamma + rw_delta;
  }
  if (isfinite(rw_sum) && rw_sum > BANDIT_PULLS_EPSILON) {
    rw_alpha /= rw_sum;
    rw_beta /= rw_sum;
    rw_gamma /= rw_sum;
    rw_delta /= rw_sum;
  }
  if (!bandit->cmp_reward) {
    rw_delta = 0.0;
    double no_cmp_sum = rw_alpha + rw_beta + rw_gamma;
    if (!isfinite(no_cmp_sum) || no_cmp_sum <= BANDIT_PULLS_EPSILON) {
      rw_alpha = 0.75;
      rw_beta = 0.20;
      rw_gamma = 0.05;
      no_cmp_sum = 1.0;
    }
    rw_alpha /= no_cmp_sum;
    rw_beta /= no_cmp_sum;
    rw_gamma /= no_cmp_sum;
  }
  /* Continuous cmp-log advancement is also progress, even when this window
     does not yet produce new coverage/new bits. */
  u8 has_progress =
      (bandit->win_new_cov > 0 || bandit->win_new_bits > 0 ||
       bandit->win_rarity_mass > BANDIT_PROGRESS_RARITY_EPS ||
       cmplog_progress > ADARARE_P90_SIGNAL_EPS)
          ? 1
          : 0;
  double thrpt_pen_eff = thrpt_pen;
  if (has_progress) {
    thrpt_pen_eff *= ADARARE_THRPT_PEN_IF_PROGRESS;
  }
  double gate_bonus_final = gate_bonus;
  u8 gate_progress_gated = (!has_progress && gate_bonus > 0.0) ? 1 : 0;
  if (!has_progress) {
    gate_bonus_final = 0.0;
  }

  double positive_reward =
      rw_alpha * edges_term + rw_beta * rarity_term + rw_delta * cmplog_term_used;
  if (!isfinite(positive_reward) || positive_reward < 0.0) positive_reward = 0.0;
  double penalty_reward = rw_gamma * thrpt_pen_eff;
  if (!isfinite(penalty_reward) || penalty_reward < 0.0) penalty_reward = 0.0;
  double gate_bonus_eff = 0.0;
  double gate_bonus_headroom = 0.0;
  if (positive_reward > ADARARE_GATE_POS_EPS && gate_bonus_final > 0.0) {
    double reward_no_gate = positive_reward - penalty_reward;
    gate_bonus_headroom = ADARARE_REWARD_POS_CAP - reward_no_gate;
    if (!isfinite(gate_bonus_headroom) || gate_bonus_headroom < 0.0) {
      gate_bonus_headroom = 0.0;
    }
    double max_bonus_by_headroom = gate_bonus_headroom / positive_reward;
    if (!isfinite(max_bonus_by_headroom) || max_bonus_by_headroom < 0.0) {
      max_bonus_by_headroom = 0.0;
    }
    gate_bonus_eff = gate_bonus_final;
    if (gate_bonus_eff > max_bonus_by_headroom) {
      gate_bonus_eff = max_bonus_by_headroom;
    }
  }
  if (!isfinite(gate_bonus_eff) || gate_bonus_eff < 0.0) gate_bonus_eff = 0.0;
  double gate_bonus_inject = positive_reward * gate_bonus_eff;
  if (!isfinite(gate_bonus_inject) || gate_bonus_inject < 0.0) {
    gate_bonus_inject = 0.0;
  }
  positive_reward += gate_bonus_inject;
  if (!isfinite(positive_reward) || positive_reward < 0.0) positive_reward = 0.0;

  double raw_reward = positive_reward - penalty_reward;
  if (!isfinite(raw_reward)) raw_reward = 0.0;
  double zero_prog_pen = 0.0;
  if (!has_progress) {
    zero_prog_pen = ADARARE_ZERO_PROGRESS_PENALTY * zp_penalty_mul;
    if (bandit->stag_trend_active) {
      u32 pa = res_arm;
      if (pa < bandit->num_arms &&
          bandit->arms[pa].zp_streak >=
              (u32)ADARARE_DWELL_EMERGENCY_ZP_STREAK) {
        double zp_stag_mul = ADARARE_ZERO_PROGRESS_PENALTY_STAG_MUL;
        if (!isfinite(zp_stag_mul) || zp_stag_mul < 0.0) zp_stag_mul = 0.0;
        if (zp_stag_mul > 1.0) zp_stag_mul = 1.0;
        zero_prog_pen *= zp_stag_mul;
      }
    }
    raw_reward -= zero_prog_pen;
  }

  double raw_reward_pre_cap = raw_reward;
  if (!isfinite(raw_reward_pre_cap)) raw_reward_pre_cap = 0.0;
  if (!isfinite(raw_reward)) raw_reward = 0.0;

  /* clamp raw_reward to keep LinUCB bounded */
  if (raw_reward > ADARARE_REWARD_POS_CAP) raw_reward = ADARARE_REWARD_POS_CAP;
  if (raw_reward < -ADARARE_REWARD_NEG_CAP) raw_reward = -ADARARE_REWARD_NEG_CAP;

  if (raw_reward < 0.0) raw_reward = 0.0;
  if (!isfinite(raw_reward)) raw_reward = 0.0;

  bandit->last_raw_reward_pre_cap = raw_reward_pre_cap;
  bandit->win_clamp_hi =
      (raw_reward_pre_cap > ADARARE_REWARD_POS_CAP) ? 1U : 0U;
  bandit->win_reward_zero = (raw_reward <= 0.0) ? 1U : 0U;
  bandit->win_has_progress = has_progress;

  double timeout_hz = (double)bandit->win_timeouts / safe_time;
  double slow_hz = (double)bandit->win_slow_execs / safe_time;

  bandit->last_thrpt = thrpt;
  bandit->last_thrpt_ref = bandit->thrpt_ref_inited ? bandit->thrpt_ref_ema : thrpt;
  bandit->last_thrpt_pen = thrpt_pen;
  bandit->last_thrpt_pen_eff = thrpt_pen_eff;
  bandit->last_p90_add_edges = p90_add_edges;
  bandit->last_p90_add_rarity = p90_add_rarity;
  bandit->last_timeout_hz = timeout_hz;
  bandit->last_slow_hz = slow_hz;
  bandit->last_delta_bits = delta_bits;
  bandit->last_delta_edges = edges_rate;
  bandit->last_delta_rarity = delta_rarity;
  bandit->last_gate_factor = gate_factor;
  bandit->last_gate_bonus = gate_bonus;
  bandit->last_gate_bonus_final = gate_bonus_final;
  bandit->last_gate_bonus_eff = gate_bonus_eff;
  bandit->last_gate_bonus_headroom = gate_bonus_headroom;
  bandit->last_gate_bonus_inject = gate_bonus_inject;
  bandit->last_gate_progress_gated = gate_progress_gated;
  bandit->last_zero_prog_pen = zero_prog_pen;
  
  bandit->last_time_sec = safe_time;
  bandit->last_edges_rate = edges_rate;
  bandit->last_rarity_rate = rarity_rate;
  bandit->last_cmplog_rate = cmplog_rate;
  bandit->last_cmplog_rate_norm = cmplog_rate_norm;
  if (!isfinite(bandit->last_cmplog_rate_norm) ||
      bandit->last_cmplog_rate_norm < 0.0) {
    bandit->last_cmplog_rate_norm = 0.0;
  }
  bandit->last_cmplog_term = cmplog_term;
  bandit->last_cmplog_mod = cmplog_mod;
  bandit->last_cmplog_inject_count = bandit->win_cmplog_inject_count;
  bandit->last_cmplog_inject_sum = bandit->win_cmplog_inject_sum;
  bandit->last_cmplog_inject_clipped_count =
      bandit->win_cmplog_inject_clipped_count;
  if (!isfinite(bandit->last_cmplog_inject_sum) ||
      bandit->last_cmplog_inject_sum < 0.0) {
    bandit->last_cmplog_inject_sum = 0.0;
  }
  bandit->last_scale_c3_used = scale_c3;
  bandit->last_p90_cmplog = p90_cmplog;
  bandit->last_reward_delta_used = rw_delta;
  bandit->last_edges_per_exec = edges_per_exec;
  bandit->last_rarity_per_exec = rarity_per_exec;
  bandit->last_edges_term = edges_term;
  bandit->last_rarity_term = rarity_term;

  u32 progress_arm = window_arm_eff;
  if (progress_arm >= bandit->num_arms) {
    progress_arm = bandit->current_arm;
    if (progress_arm >= bandit->num_arms) progress_arm = 0;
  }
  if (progress_arm < bandit->num_arms) {
    if (!has_progress) {
      if (bandit->arms[progress_arm].zp_streak < UINT_MAX) {
        bandit->arms[progress_arm].zp_streak++;
      }
    } else if (bandit->arms[progress_arm].zp_streak > 0) {
      bandit->arms[progress_arm].zp_streak--;
    }
  }

  if (bandit->current_arm < bandit->num_arms &&
      bandit->current_arm < AFL_BANDIT_MAX_ARMS) {
    bandit->arms[bandit->current_arm].last_thrpt = thrpt;
    bandit->arms[bandit->current_arm].last_seen_ms = entry_now_ms;
  }

  /* ============================================================ */
  /* 4. Update Stats & Snapshot                                   */
  /* ============================================================ */

  if (bandit->discount > 0.0 && bandit->discount < 1.0) {
    for (u32 i = 0; i < bandit->num_arms; ++i) {
      bandit->arms[i].pulls *= bandit->discount;
      bandit->arms[i].total_reward *= bandit->discount;
      
      if (bandit->use_contextual) {
          for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
             for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
                bandit->arms[i].A[r][c] *= bandit->discount;
             }
             bandit->arms[i].b[r] *= bandit->discount;
             bandit->arms[i].A[r][r] += (1.0 - bandit->discount) * bandit->ridge_lambda;
          }
          /* Fix P1: Enforce Symmetry after discount */
          for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
              for (int c = r + 1; c < BANDIT_CTX_DIM; ++c) {
                  bandit->arms[i].A[c][r] = bandit->arms[i].A[r][c];
              }
          }
      }
    }
    bandit->total_rounds *= bandit->discount;
  }

  double final_reward = bandit_normalize_reward(raw_reward);
  double arm_weights[AFL_BANDIT_MAX_ARMS] = {0.0};
  u64 win_total_ms = 0;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    win_total_ms += bandit->win_arm_ms[i];
  }

  if (win_total_ms > 0) {
    double inv_total_ms = 1.0 / (double)win_total_ms;
    for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
      if (bandit->win_arm_ms[i] > 0) {
        arm_weights[i] = (double)bandit->win_arm_ms[i] * inv_total_ms;
      }
    }
  } else {
    u32 fallback_arm = bandit->current_arm;
    if (fallback_arm >= bandit->num_arms || fallback_arm >= AFL_BANDIT_MAX_ARMS) {
      fallback_arm = BANDIT_ARM_A1;
      if (fallback_arm >= bandit->num_arms || fallback_arm >= AFL_BANDIT_MAX_ARMS) {
        fallback_arm = 0;
      }
    }
    arm_weights[fallback_arm] = 1.0;
  }

  u32 ema_arm = window_arm_eff;
  double best_w = -1.0;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    if (arm_weights[i] > best_w) {
      best_w = arm_weights[i];
      ema_arm = i;
    }
  }
  if (ema_arm >= bandit->num_arms) {
    ema_arm = (window_arm_eff < bandit->num_arms) ? window_arm_eff : 0;
  }
  if (ema_arm < bandit->num_arms) {
    double observed_edges = edges_rate;
    double observed_edges_per_exec = edges_per_exec;
    double observed_rarity_per_exec = rarity_per_exec;
    if (!isfinite(observed_edges) || observed_edges < 0.0) observed_edges = 0.0;
    if (!isfinite(observed_edges_per_exec) || observed_edges_per_exec < 0.0) {
      observed_edges_per_exec = 0.0;
    }
    if (!isfinite(observed_rarity_per_exec) || observed_rarity_per_exec < 0.0) {
      observed_rarity_per_exec = 0.0;
    }
    double prev_ema = bandit->arms[ema_arm].edges_ema;
    if (!isfinite(prev_ema) || prev_ema < 0.0) prev_ema = 0.0;
    if (prev_ema <= 0.0) {
      bandit->arms[ema_arm].edges_ema = observed_edges;
    } else {
      bandit->arms[ema_arm].edges_ema =
          (1.0 - ADARARE_EDGES_EMA_ALPHA) * prev_ema +
          ADARARE_EDGES_EMA_ALPHA * observed_edges;
    }

    if (bandit->arms[ema_arm].pulls < ADARARE_EARLY_EDGES_PULLS_CUTOFF) {
      double prev_early = bandit->arms[ema_arm].early_edges_ema;
      if (!isfinite(prev_early) || prev_early < 0.0) prev_early = 0.0;
      if (prev_early <= 0.0) {
        bandit->arms[ema_arm].early_edges_ema = observed_edges;
      } else {
        bandit->arms[ema_arm].early_edges_ema =
            (1.0 - ADARARE_EDGES_EMA_ALPHA) * prev_early +
            ADARARE_EDGES_EMA_ALPHA * observed_edges;
      }
    }

    double prev_edges_exec = bandit->arms[ema_arm].edges_per_exec_ema;
    if (!isfinite(prev_edges_exec) || prev_edges_exec < 0.0) prev_edges_exec = 0.0;
    if (prev_edges_exec <= 0.0) {
      bandit->arms[ema_arm].edges_per_exec_ema = observed_edges_per_exec;
    } else {
      bandit->arms[ema_arm].edges_per_exec_ema =
          (1.0 - ADARARE_EDGES_EMA_ALPHA) * prev_edges_exec +
          ADARARE_EDGES_EMA_ALPHA * observed_edges_per_exec;
    }

    double prev_rarity_exec = bandit->arms[ema_arm].rarity_per_exec_ema;
    if (!isfinite(prev_rarity_exec) || prev_rarity_exec < 0.0) {
      prev_rarity_exec = 0.0;
    }
    if (prev_rarity_exec <= 0.0) {
      bandit->arms[ema_arm].rarity_per_exec_ema = observed_rarity_per_exec;
    } else {
      bandit->arms[ema_arm].rarity_per_exec_ema =
          (1.0 - ADARARE_EDGES_EMA_ALPHA) * prev_rarity_exec +
          ADARARE_EDGES_EMA_ALPHA * observed_rarity_per_exec;
    }
  }

  u64 selection_round = bandit->total_selections + 1;
  double pulls_credit = 0.0;
  for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
    double weight = arm_weights[i];
    if (weight <= 0.0) { continue; }

    bandit_arm_state_t *arm = &bandit->arms[i];
    arm->pulls += weight;
    arm->warmup_pulls += weight;
    arm->total_reward += final_reward * weight;
    arm->selections++;
    arm->last_selected_round = selection_round;
    arm->last_selected_ms = entry_now_ms;
    pulls_credit += weight;
  }

  if (pulls_credit <= 0.0) {
    current->pulls += 1.0;
    current->warmup_pulls += 1.0;
    current->total_reward += final_reward;
    current->selections++;
    current->last_selected_round = selection_round;
    current->last_selected_ms = entry_now_ms;
    pulls_credit = 1.0;
  }

  bandit->total_rounds += pulls_credit;
  bandit->total_selections = selection_round;
  
  bandit->last_arm_used = bandit->current_arm;
  bandit->last_arm_eff_used = window_arm_eff;
  bandit->last_mix_choice = bandit->mix_choice;
  bandit->last_reward = final_reward; 
  bandit->last_raw_reward = raw_reward;   
  
  bandit->last_win_execs       = bandit->win_execs;
  bandit->last_win_time_us     = bandit->win_time_us;
  bandit->last_win_new_cov     = bandit->win_new_cov;
  bandit->last_win_new_bits    = bandit->win_new_bits;
  bandit->last_win_clamp_hi    = bandit->win_clamp_hi;
  bandit->last_win_guard_hits  = bandit->win_guard_hits;
  bandit->last_win_trend_active = bandit->win_trend_active;
  bandit->last_win_reward_zero = bandit->win_reward_zero;
  bandit->last_win_has_progress = bandit->win_has_progress;
  bandit->last_win_novelty     = bandit->win_novelty;
  bandit->last_win_rarity_mass = bandit->win_rarity_mass;
  bandit->last_win_timeouts    = bandit->win_timeouts;
  bandit->last_win_slow_execs  = bandit->win_slow_execs;
  
  bandit->last_win_gate = bandit->win_gate_samples 
      ? bandit->win_gate_sum / bandit->win_gate_samples : 0.0;
  bandit->last_win_gate_execavg = bandit->win_gate_exec_samples 
      ? bandit->win_gate_exec_sum / bandit->win_gate_exec_samples : 0.0;

  double trend_edges_signal = log1p(edges_rate);
  if (!isfinite(trend_edges_signal) || trend_edges_signal < 0.0) {
    trend_edges_signal = 0.0;
  }
  if (!bandit->stag_trend_inited) {
    bandit->stag_ema_reward = final_reward;
    bandit->stag_ema_edges = trend_edges_signal;
    bandit->stag_slope_reward = 0.0;
    bandit->stag_slope_edges = 0.0;
    bandit->stag_trend_inited = 1;
  } else {
    double prev_ema_reward = bandit->stag_ema_reward;
    double prev_ema_edges = bandit->stag_ema_edges;
    bandit->stag_ema_reward =
        (1.0 - BANDIT_STAG_TREND_ALPHA) * bandit->stag_ema_reward +
        BANDIT_STAG_TREND_ALPHA * final_reward;
    bandit->stag_ema_edges =
        (1.0 - BANDIT_STAG_TREND_ALPHA) * bandit->stag_ema_edges +
        BANDIT_STAG_TREND_ALPHA * trend_edges_signal;

    double inst_reward_slope = bandit->stag_ema_reward - prev_ema_reward;
    double inst_edges_slope = bandit->stag_ema_edges - prev_ema_edges;
    bandit->stag_slope_reward =
        (1.0 - BANDIT_STAG_SLOPE_ALPHA) * bandit->stag_slope_reward +
        BANDIT_STAG_SLOPE_ALPHA * inst_reward_slope;
    bandit->stag_slope_edges =
        (1.0 - BANDIT_STAG_SLOPE_ALPHA) * bandit->stag_slope_edges +
        BANDIT_STAG_SLOPE_ALPHA * inst_edges_slope;
  }

  u8 trend_ready =
      (bandit->stag_trend_inited &&
       bandit->total_selections >= BANDIT_STAG_TREND_MIN_WINDOWS)
          ? 1
          : 0;
  u8 trend_stagnating =
      (trend_ready &&
       fabs(bandit->stag_slope_reward) < BANDIT_STAG_REWARD_SLOPE_EPS &&
       fabs(bandit->stag_slope_edges) < BANDIT_STAG_EDGES_SLOPE_EPS)
          ? 1
          : 0;
  bandit->stag_trend_active = trend_stagnating;
  bandit->win_trend_active = trend_stagnating;

  if (bandit->win_new_cov > 0 || bandit->win_new_bits > 0) {
    bandit->stagnation_windows = 0;
    bandit->last_improve_ms = entry_now_ms;
    bandit->stag_trend_active = 0;
    bandit->win_trend_active = 0;
  } else if (trend_stagnating && bandit->stagnation_windows < UINT_MAX) {
    bandit->stagnation_windows++;
  } else if (bandit->stagnation_windows > 0) {
    bandit->stagnation_windows--;
  }
      
  bandit->linucb_invert_fail_last = bandit->linucb_invert_fail_win;
  bandit->linucb_rad_cap_hits_last = bandit->linucb_rad_cap_hits_win;
  bandit->linucb_score_cap_hits_last = bandit->linucb_score_cap_hits_win;
  
  bandit->linucb_invert_fail_win = 0;
  bandit->linucb_rad_cap_hits_win = 0;
  bandit->linucb_score_cap_hits_win = 0;
  
  bandit_reservoir_t *score_res = (bandit_reservoir_t*)bandit->score_res;
  
  reservoir_add(score_res, raw_reward, bandit_get_random(bandit), bandit_get_random(bandit));
  
  double p90v = reservoir_p90(score_res);
  bandit->last_p90_n = score_res->count;
  bandit->last_p90_valid = (score_res->count >= BANDIT_P90_MIN_SAMPLES) && isfinite(p90v) && p90v > 0.0;
  if (!bandit->last_p90_valid) p90v = 1.0;
  bandit->last_p90_score = p90v;
  
  if (win_id % BANDIT_RESCALE_INTERVAL == 0) {
      /* Keep edges/rarity reservoirs warm; reset only score telemetry reservoir. */
      reservoir_reset((bandit_reservoir_t*)bandit->score_res);
  }

  /* ============================================================ */
  /* 5. Selection (Warmup + Stagnation-aware UCB/Revisit)         */
  /* ============================================================ */

  u32 next_arm = bandit->current_arm;
  bandit_build_a6_topk(bandit);
  
  double raw_x[BANDIT_CTX_DIM];
  double x[BANDIT_CTX_DIM];
  double vc = (double)bandit->last_win_new_bits / safe_time;
  double vr = bandit->last_win_rarity_mass / safe_time;
  double thrpt_ctx = (double)bandit->last_win_execs / safe_time;
  
  u64 q_paths = (bandit->owner ? (u64)bandit->owner->queued_items : 0);
  double corpus = (bandit->owner ? (double)bandit->owner->active_items : 1.0);
  if (corpus < 1.0) corpus = 1.0;
  double q_rel = corpus > 0.0 ? (double)q_paths / corpus : 0.0;
  double favored_ratio = 0.0;
  if (bandit->owner) {
    double q_items = (double)bandit->owner->queued_items;
    if (q_items < 1.0) q_items = 1.0;
    favored_ratio = (double)bandit->owner->queued_favored / q_items;
  }
  double p_timeout = (double)bandit->last_win_timeouts / (double)(bandit->last_win_execs ? bandit->last_win_execs : 1);

  raw_x[0] = bandit_clamp_feature(log1p(vc) * BANDIT_X0_SCALE);
  raw_x[1] = bandit_clamp_feature(log1p(vr) * BANDIT_X1_SCALE);
  raw_x[2] = bandit_clamp_feature(log1p(thrpt_ctx) * BANDIT_X2_SCALE);
  raw_x[3] = bandit_clamp_feature(log1p(q_rel) * BANDIT_X3_SCALE);
  raw_x[4] = bandit_clamp_feature(favored_ratio * BANDIT_X4_SCALE);
  raw_x[5] = bandit_clamp_feature(log1p(p_timeout) * BANDIT_X5_SCALE);
  for (int k = 0; k < BANDIT_CTX_DIM; ++k) {
    if (!isfinite(raw_x[k])) raw_x[k] = 0.0;
    bandit->last_raw_x[k] = raw_x[k];
  }

  double ctx_ema_alpha = ADARARE_CTX_EMA_ALPHA;
  if (!isfinite(ctx_ema_alpha)) ctx_ema_alpha = 0.0;
  if (ctx_ema_alpha < 0.0) ctx_ema_alpha = 0.0;
  if (ctx_ema_alpha > 1.0) ctx_ema_alpha = 1.0;

  if (!bandit->x_ema_inited) {
    for (int k = 0; k < BANDIT_CTX_DIM; ++k) {
      x[k] = raw_x[k];
      bandit->last_x[k] = x[k];
    }
    bandit->x_ema_inited = 1;
  } else {
    for (int k = 0; k < BANDIT_CTX_DIM; ++k) {
      double prev_x = bandit->last_x[k];
      if (!isfinite(prev_x)) prev_x = raw_x[k];
      x[k] = (1.0 - ctx_ema_alpha) * prev_x + ctx_ema_alpha * raw_x[k];
      if (!isfinite(x[k])) x[k] = raw_x[k];
      bandit->last_x[k] = x[k];
    }
  }

  if (bandit->use_contextual) {
    for (u32 i = 0; i < bandit->num_arms && i < AFL_BANDIT_MAX_ARMS; ++i) {
      if (arm_weights[i] > 0.0) {
        bandit_update_arm_model(bandit, &bandit->arms[i], x, final_reward,
                                arm_weights[i]);
      }
    }
  }

  bandit->last_a6_eta_eff = 0.0;
  bandit->last_a6_eta_stats = 0.0;
  bandit->last_a6_eta_model = 0.0;
  bandit->last_a6_pi_eff = 0.0;
  bandit->last_a6_ips_w = 1.0;
  bandit->last_a6_eff_arm = BANDIT_ARM_A6;
  bandit->last_mix_p_used = bandit->mix_p;
  bandit->last_mix_p_next = bandit->mix_p;
  if (bandit->current_arm == BANDIT_ARM_A6 && window_arm_eff < bandit->num_arms &&
      window_arm_eff != bandit->current_arm) {

    bandit->last_a6_eff_arm = window_arm_eff;
    double mix_p_used = bandit->mix_p;
    if (!isfinite(mix_p_used)) mix_p_used = 0.5;
    if (mix_p_used < ADARARE_MIX_P_MIN) mix_p_used = ADARARE_MIX_P_MIN;
    if (mix_p_used > ADARARE_MIX_P_MAX) mix_p_used = ADARARE_MIX_P_MAX;
    bandit->last_mix_p_used = mix_p_used;

    if (window_arm_eff == BANDIT_ARM_A1 || window_arm_eff == BANDIT_ARM_A2) {
      if (window_arm_eff == BANDIT_ARM_A1) {
        bandit->a6_to_a1++;
        double old_q = bandit->a6_q1;
        if (!isfinite(old_q) || old_q < 0.0) old_q = 0.0;
        bandit->a6_q1 = (old_q <= 0.0)
                            ? final_reward
                            : (1.0 - ADARARE_A6_MIX_EMA_ALPHA) * old_q +
                                  ADARARE_A6_MIX_EMA_ALPHA * final_reward;
      } else {
        bandit->a6_to_a2++;
        double old_q = bandit->a6_q2;
        if (!isfinite(old_q) || old_q < 0.0) old_q = 0.0;
        bandit->a6_q2 = (old_q <= 0.0)
                            ? final_reward
                            : (1.0 - ADARARE_A6_MIX_EMA_ALPHA) * old_q +
                                  ADARARE_A6_MIX_EMA_ALPHA * final_reward;
      }
    }

    double sub_progress = has_progress ? 1.0 : 0.0;
    if (bandit->a6_sub_samples == 0) {
      bandit->a6_sub_progress_ema = sub_progress;
    } else {
      double old_sub_progress = bandit->a6_sub_progress_ema;
      if (!isfinite(old_sub_progress) || old_sub_progress < 0.0) {
        old_sub_progress = sub_progress;
      }
      bandit->a6_sub_progress_ema =
          (1.0 - ADARARE_A6_MIX_EMA_ALPHA) * old_sub_progress +
          ADARARE_A6_MIX_EMA_ALPHA * sub_progress;
    }
    if (!isfinite(bandit->a6_sub_progress_ema) || bandit->a6_sub_progress_ema < 0.0) {
      bandit->a6_sub_progress_ema = 0.0;
    }
    if (bandit->a6_sub_progress_ema > 1.0) bandit->a6_sub_progress_ema = 1.0;
    if (bandit->a6_sub_samples < ULLONG_MAX) bandit->a6_sub_samples++;

#if ADARARE_ENABLE_ADAPTIVE_A6
    if (bandit->a6_sub_samples >= ADARARE_A6_MIX_MIN_SAMPLES &&
        (bandit->a6_sub_samples % ADARARE_MIX_UPDATE_INTERVAL) == 0) {
      double q1 = bandit->a6_q1;
      double q2 = bandit->a6_q2;
      if (!isfinite(q1) || q1 < 0.0) q1 = 0.0;
      if (!isfinite(q2) || q2 < 0.0) q2 = 0.0;
      double tanh_scale = ADARARE_A6_MIX_TANH_SCALE;
      if (!isfinite(tanh_scale) || tanh_scale <= BANDIT_PULLS_EPSILON) {
        tanh_scale = 0.05;
      }
      double target = 0.5 + 0.5 * tanh((q2 - q1) / tanh_scale);
      if (!isfinite(target)) target = mix_p_used;
      double new_p =
          (1.0 - ADARARE_A6_MIX_EMA) * mix_p_used +
          ADARARE_A6_MIX_EMA * target;
      if (!isfinite(new_p)) new_p = mix_p_used;
      bandit->mix_p = new_p;
      if (bandit->mix_p < ADARARE_MIX_P_MIN) bandit->mix_p = ADARARE_MIX_P_MIN;
      if (bandit->mix_p > ADARARE_MIX_P_MAX) bandit->mix_p = ADARARE_MIX_P_MAX;
    }
#endif
    bandit->last_mix_p_next = bandit->mix_p;

    double pi = bandit->a6_choice_pi;
    if (!isfinite(pi) || pi <= 0.0) {
      pi = 1.0 / (double)ADARARE_A6_TOPK;
    }
    if (!isfinite(pi) || pi < ADARARE_IPS_PI_EPS) pi = ADARARE_IPS_PI_EPS;
    if (pi > 1.0) pi = 1.0;
    bandit->last_a6_pi_eff = pi;
    double ips_w = ADARARE_A6_BASE_ETA;
    if (bandit->a6_offpolicy_mode != BANDIT_A6_OFFPOLICY_FIXED) {
      ips_w = 1.0 / pi;
      if (!isfinite(ips_w) || ips_w < 1.0) ips_w = 1.0;
      if (bandit->a6_offpolicy_mode == BANDIT_A6_OFFPOLICY_CLIPPED_IPS &&
          ips_w > ADARARE_IPS_CLIP) {
        ips_w = ADARARE_IPS_CLIP;
      }
    }
    if (!isfinite(ips_w) || ips_w <= 0.0) ips_w = ADARARE_A6_BASE_ETA;
    bandit->last_a6_ips_w = ips_w;

    double eta = ips_w;
    bandit->last_a6_eta_eff = eta;
    bandit->last_a6_eta_stats = eta;
    bandit->last_a6_eta_model = eta;

    bandit_arm_state_t *eff_arm = &bandit->arms[window_arm_eff];
    eff_arm->pulls += eta;
    eff_arm->warmup_pulls += eta;
    eff_arm->total_reward += final_reward * eta;
    if (eff_arm->total_reward > eff_arm->pulls) {
      eff_arm->total_reward = eff_arm->pulls;
    }
    eff_arm->selections += 1;
    eff_arm->last_selected_round = bandit->total_selections;
    if (bandit->use_contextual) {
      bandit_update_arm_model(bandit, eff_arm, x, final_reward, eta);
    }
  }

  double score_pred_dbg[AFL_BANDIT_MAX_ARMS];
  double score_bonus_dbg[AFL_BANDIT_MAX_ARMS];
  double score_total_dbg[AFL_BANDIT_MAX_ARMS];
  double score_guard_ratio_dbg[AFL_BANDIT_MAX_ARMS];
  double score_guard_factor_dbg[AFL_BANDIT_MAX_ARMS];
  u32 score_guard_streak_dbg[AFL_BANDIT_MAX_ARMS];
  double score_zp_factor_dbg[AFL_BANDIT_MAX_ARMS];
  u8 score_zp_applied_dbg[AFL_BANDIT_MAX_ARMS];
  u32 guard_hits = 0;
  u32 tie_break_hits = 0;
  u32 tie_break_det_hits = 0;
  double tie_eps_observed = 0.0;
  u8 dwell_blocked = 0;
  u8 dwell_emergency_zero = 0;
  for (u32 i = 0; i < AFL_BANDIT_MAX_ARMS; ++i) {
    score_pred_dbg[i] = NAN;
    score_bonus_dbg[i] = NAN;
    score_total_dbg[i] = NAN;
    score_guard_ratio_dbg[i] = 1.0;
    score_guard_factor_dbg[i] = 1.0;
    score_guard_streak_dbg[i] = 0;
    score_zp_factor_dbg[i] = 1.0;
    score_zp_applied_dbg[i] = 0;
  }

  bandit->in_warmup = bandit_in_pulls_warmup(bandit);
  bandit->last_warmup_min_pulls = bandit_min_warmup_pulls(bandit);
  u32 dyn_stag_thresh = BANDIT_STAG_WINDOWS;
#if ADARARE_STAG_DYN_ENABLE
  double rounds = bandit->total_rounds;
  if (!isfinite(rounds) || rounds < 0.0) rounds = 0.0;
  u32 dyn_thresh_m1 = BANDIT_STAG_WINDOWS * ADARARE_STAG_DYN_M1;
  u32 dyn_thresh_m2 = BANDIT_STAG_WINDOWS * ADARARE_STAG_DYN_M2;
  if (!dyn_thresh_m1) dyn_thresh_m1 = BANDIT_STAG_WINDOWS;
  if (!dyn_thresh_m2) dyn_thresh_m2 = BANDIT_STAG_WINDOWS;
  if (rounds > ADARARE_STAG_DYN_R2) {
    dyn_stag_thresh = dyn_thresh_m2;
  } else if (rounds > ADARARE_STAG_DYN_R1) {
    dyn_stag_thresh = dyn_thresh_m1;
  }
#endif
  if (!dyn_stag_thresh) dyn_stag_thresh = BANDIT_STAG_WINDOWS;
  bandit->last_dyn_stag_thresh = dyn_stag_thresh;
  u8 stagnating = (bandit->stagnation_windows >= dyn_stag_thresh) ? 1 : 0;
  u8 force_revisit = 0;
  u8 stag_bonus_boost = 0;
  bandit->last_stag_bonus_boost = 0;

  if (bandit->in_warmup) {
    next_arm = bandit_argmin_pulls(bandit);
  } else if (stagnating &&
             (!bandit->last_revisit_ms ||
              entry_now_ms - bandit->last_revisit_ms >= bandit->revisit_time_ms)) {
    next_arm = bandit_pick_revisit_arm(bandit);
    bandit->last_revisit_ms = entry_now_ms;
    force_revisit = 1;
  } else {
    double best_score = -DBL_MAX;
    double best_early_edges_metric = 0.0;
    double best_edges_metric = 0.0;
    double best_rarity_metric = 0.0;
    double best_eff_metric = 0.0;
    double best_speed_metric = 0.0;
    double log_t =
        log((double)(bandit->total_selections > 1 ? bandit->total_selections : 1));
    double stagnation_bonus_mul = 1.0;
    if (stagnating) {
      double over =
          (double)(bandit->stagnation_windows - dyn_stag_thresh + 1U);
      double ramp = over / (double)dyn_stag_thresh;
      if (ramp > 1.0) ramp = 1.0;
      stagnation_bonus_mul = 1.0 + (BANDIT_STAG_BOOST - 1.0) * ramp;
    }
    stag_bonus_boost = (stagnation_bonus_mul > 1.0 + BANDIT_PULLS_EPSILON) ? 1 : 0;
    bandit->last_stag_bonus_boost = stag_bonus_boost;

    for (u32 i = 0; i < bandit->num_arms; ++i) {
      double score = 0.0;
      double pred = 0.0;
      double bonus = 0.0;
      double guard_ratio = 1.0;
      double guard_factor = 1.0;
      u32 guard_streak = bandit->arms[i].guard_streak;
      double zp_factor = 1.0;
      u8 zp_applied = 0;

      if (bandit->arms[i].selections == 0) {
        pred = 0.0;
        bonus = 1e9;
        score = 1e9;
      } else if (bandit->use_contextual) {
        double Ainv[BANDIT_CTX_DIM][BANDIT_CTX_DIM];
        if (!invert6((const double(*)[BANDIT_CTX_DIM])bandit->arms[i].A, Ainv)) {
          bandit->linucb_invert_fail_win++;
          bandit->linucb_invert_fail_total++;
          double pulls = bandit->arms[i].pulls;
          if (pulls < BANDIT_PULLS_EPSILON) pulls = BANDIT_PULLS_EPSILON;
          pred = bandit->arms[i].total_reward / pulls;
          bonus = sqrt((2.0 * log_t) / pulls);
          if (bonus > BANDIT_BONUS_CAP) bonus = BANDIT_BONUS_CAP;
          bonus *= stagnation_bonus_mul;
          score = pred + bonus;
        } else {
          double theta[BANDIT_CTX_DIM] = {0};
          for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
            for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
              theta[r] += Ainv[r][c] * bandit->arms[i].b[c];
            }
          }
          pred = 0.0;
          for (int k = 0; k < BANDIT_CTX_DIM; ++k) pred += theta[k] * x[k];
          double tmp[BANDIT_CTX_DIM] = {0};
          for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
            for (int c = 0; c < BANDIT_CTX_DIM; ++c) tmp[r] += Ainv[r][c] * x[c];
          }
          double rad = 0.0;
          for (int k = 0; k < BANDIT_CTX_DIM; ++k) rad += x[k] * tmp[k];
          if (rad < 0.0 || !isfinite(rad)) rad = 0.0;
          rad = sqrt(rad);
          if (rad > 10.0) {
            bandit->linucb_rad_cap_hits_win++;
            bandit->linucb_rad_cap_hits_total++;
            rad = 10.0;
          }
          bonus = bandit->alpha * rad * stagnation_bonus_mul;
          score = pred + bonus;
          if (score < 0.0) score = 0.0;
          if (!isfinite(score)) score = 0.0;
          if (score > 5.0) {
            bandit->linucb_score_cap_hits_win++;
            bandit->linucb_score_cap_hits_total++;
            score = 5.0;
          }
          bonus = score - pred;
        }
      } else {
        double pulls = bandit->arms[i].pulls;
        if (pulls < BANDIT_PULLS_EPSILON) pulls = BANDIT_PULLS_EPSILON;
        pred = bandit->arms[i].total_reward / pulls;
        if (pred < 0.0) pred = 0.0;
        if (pred > 1.0) pred = 1.0;
        bonus = sqrt((2.0 * log_t) / pulls);
        if (bonus > BANDIT_BONUS_CAP) bonus = BANDIT_BONUS_CAP;
        bonus *= stagnation_bonus_mul;
        score = pred + bonus;
      }

#if BANDIT_SEL_THRPT_GUARD
      if (bandit->thrpt_ref_inited && bandit->thrpt_ref_ema > 1e-9 &&
          bandit->arms[i].last_seen_ms > 0) {
        double arm_thrpt = bandit->arms[i].last_thrpt;
        if (!isfinite(arm_thrpt) || arm_thrpt < 0.0) arm_thrpt = 0.0;

        guard_ratio = arm_thrpt / bandit->thrpt_ref_ema;
        if (!isfinite(guard_ratio) || guard_ratio < 0.0) guard_ratio = 0.0;
        if (guard_ratio < BANDIT_THRPT_GUARD_RATIO) {
          double norm =
              guard_ratio / (BANDIT_THRPT_GUARD_RATIO + BANDIT_PULLS_EPSILON);
          if (norm < 0.0) norm = 0.0;
          if (norm > 1.0) norm = 1.0;
          double deficit = 1.0 - norm;
          double soft_penalty = 1.0 - BANDIT_THRPT_GUARD_SOFT_K * deficit;
          if (soft_penalty > 1.0) soft_penalty = 1.0;
          if (soft_penalty < BANDIT_THRPT_GUARD_PENALTY_MIN) {
            soft_penalty = BANDIT_THRPT_GUARD_PENALTY_MIN;
          }
          if (guard_streak < UINT_MAX) guard_streak++;
          if (guard_streak > BANDIT_THRPT_GUARD_STREAK_START) {
            double extra =
                (double)(guard_streak - BANDIT_THRPT_GUARD_STREAK_START) *
                BANDIT_THRPT_GUARD_STREAK_STEP;
            soft_penalty -= extra;
            if (soft_penalty < BANDIT_THRPT_GUARD_PENALTY_MIN) {
              soft_penalty = BANDIT_THRPT_GUARD_PENALTY_MIN;
            }
          }
          score *= soft_penalty;
          guard_factor = soft_penalty;
          guard_hits++;
        } else if (guard_streak > 0) {
          guard_streak--;
        }
      }
#endif

      if (bandit->arms[i].zp_streak >= ADARARE_ZP_STREAK_START) {
        double drop = (double)(bandit->arms[i].zp_streak - ADARARE_ZP_STREAK_START) *
                      ADARARE_ZP_STEP;
        zp_factor = 1.0 - drop;
        if (zp_factor < ADARARE_ZP_FACTOR_MIN) zp_factor = ADARARE_ZP_FACTOR_MIN;
        if (zp_factor > 1.0) zp_factor = 1.0;
        score *= zp_factor;
        zp_applied = (zp_factor < 1.0) ? 1 : 0;
      }

      bandit->arms[i].guard_streak = guard_streak;

      if (!isfinite(score)) score = 0.0;

      if (i < AFL_BANDIT_MAX_ARMS) {
        score_pred_dbg[i] = pred;
        score_bonus_dbg[i] = bonus;
        score_total_dbg[i] = score;
        score_guard_ratio_dbg[i] = guard_ratio;
        score_guard_factor_dbg[i] = guard_factor;
        score_guard_streak_dbg[i] = guard_streak;
        score_zp_factor_dbg[i] = zp_factor;
        score_zp_applied_dbg[i] = zp_applied;
      }

      double cur_pulls_metric = bandit->arms[i].pulls;
      if (!isfinite(cur_pulls_metric) || cur_pulls_metric < 0.0) {
        cur_pulls_metric = 0.0;
      }
      double cur_early_edges = bandit->arms[i].early_edges_ema;
      if (!isfinite(cur_early_edges) || cur_early_edges < 0.0) {
        cur_early_edges = 0.0;
      }
      if (cur_pulls_metric >= ADARARE_EARLY_EDGES_PULLS_CUTOFF) {
        cur_early_edges = 0.0;
      }
      double cur_edges = bandit->arms[i].edges_ema;
      if (!isfinite(cur_edges) || cur_edges < 0.0) cur_edges = 0.0;
      double cur_rarity = bandit->arms[i].rarity_per_exec_ema;
      if (!isfinite(cur_rarity) || cur_rarity < 0.0) cur_rarity = 0.0;
      double cur_eff = bandit->arms[i].edges_per_exec_ema;
      if (!isfinite(cur_eff) || cur_eff < 0.0) cur_eff = 0.0;
      double cur_speed = bandit->arms[i].last_thrpt;
      if (!isfinite(cur_speed) || cur_speed < 0.0) cur_speed = 0.0;

      double tie_eps = 0.0;
      if (isfinite(best_score) && best_score > -DBL_MAX / 4.0) {
        double tie_ref = fmax(1.0, fmax(fabs(score), fabs(best_score)));
        tie_eps = ADARARE_TIE_EPS_REL * tie_ref;
      }
      if (tie_eps > tie_eps_observed) tie_eps_observed = tie_eps;
      if (score > best_score + tie_eps) {
        best_score = score;
        best_early_edges_metric = cur_early_edges;
        best_edges_metric = cur_edges;
        best_rarity_metric = cur_rarity;
        best_eff_metric = cur_eff;
        best_speed_metric = cur_speed;
        next_arm = i;
      } else if (ADARARE_ENABLE_TIE_BREAK &&
                 fabs(score - best_score) <= tie_eps) {
        u8 is_better_tie = 0;
        u8 is_det_tie = 0;
        if (cur_early_edges > best_early_edges_metric + BANDIT_PULLS_EPSILON) {
          is_better_tie = 1;
        } else if (fabs(cur_early_edges - best_early_edges_metric) <=
                   BANDIT_PULLS_EPSILON) {
          if (cur_edges > best_edges_metric + BANDIT_PULLS_EPSILON) {
            is_better_tie = 1;
          } else if (fabs(cur_edges - best_edges_metric) <=
                     BANDIT_PULLS_EPSILON) {
            if (cur_rarity > best_rarity_metric + BANDIT_PULLS_EPSILON) {
              is_better_tie = 1;
            } else if (fabs(cur_rarity - best_rarity_metric) <=
                       BANDIT_PULLS_EPSILON) {
              if (cur_eff > best_eff_metric + BANDIT_PULLS_EPSILON) {
                is_better_tie = 1;
              } else if (fabs(cur_eff - best_eff_metric) <=
                             BANDIT_PULLS_EPSILON) {
                if (cur_speed > best_speed_metric + BANDIT_PULLS_EPSILON) {
                  is_better_tie = 1;
                } else if (fabs(cur_speed - best_speed_metric) <=
                               BANDIT_PULLS_EPSILON &&
                           i < next_arm) {
                  is_better_tie = 1;
                  is_det_tie = 1;
                }
              }
            }
          }
        }

        if (is_better_tie) {
          best_early_edges_metric = cur_early_edges;
          best_edges_metric = cur_edges;
          best_rarity_metric = cur_rarity;
          best_eff_metric = cur_eff;
          best_speed_metric = cur_speed;
          next_arm = i;
          tie_break_hits++;
          bandit->tie_break_hits_total++;
          if (is_det_tie) {
            tie_break_det_hits++;
            bandit->tie_break_det_hits_total++;
          }
        }
      }
    }
  }

  if (prev_arm_idx < bandit->num_arms) {
    dwell_emergency_zero =
        (bandit->arms[prev_arm_idx].zp_streak >=
         (u32)ADARARE_DWELL_EMERGENCY_ZP_STREAK)
            ? 1
            : 0;
  }

  if (!bandit->in_warmup && !force_revisit && !bandit->stag_trend_active &&
      !dwell_emergency_zero &&
      next_arm != prev_arm_idx &&
      bandit->dwell_windows < ADARARE_MIN_DWELL_WINDOWS) {
    next_arm = prev_arm_idx;
    dwell_blocked = 1;
  }
  bandit->last_dwell_blocked = dwell_blocked;
  bandit->last_dwell_emergency_zero = dwell_emergency_zero;

  if (next_arm < AFL_BANDIT_MAX_ARMS && !isfinite(score_total_dbg[next_arm])) {
    score_pred_dbg[next_arm] = bandit_arm_mean_reward(&bandit->arms[next_arm]);
    score_bonus_dbg[next_arm] = 0.0;
    score_total_dbg[next_arm] = score_pred_dbg[next_arm];
  }

  bandit->last_ucb_score = (next_arm < AFL_BANDIT_MAX_ARMS &&
                            isfinite(score_total_dbg[next_arm]))
                               ? score_total_dbg[next_arm]
                               : 0.0;
  bandit->tie_break_hits_win = tie_break_hits;
  bandit->tie_break_det_hits_win = tie_break_det_hits;
  bandit->last_tie_break_det = tie_break_det_hits ? 1 : 0;
  bandit->last_tie_eps = tie_eps_observed;
  bandit->win_guard_hits = guard_hits;
  bandit->last_win_guard_hits = guard_hits;
  bandit->last_win_clamp_hi = bandit->win_clamp_hi;
  bandit->last_win_trend_active = bandit->win_trend_active;
  bandit->last_win_reward_zero = bandit->win_reward_zero;
  bandit->last_guard_arm = next_arm;
  bandit->last_guard_penalty =
      (next_arm < AFL_BANDIT_MAX_ARMS &&
       isfinite(score_guard_factor_dbg[next_arm]))
          ? score_guard_factor_dbg[next_arm]
          : 1.0;
  bandit->last_guard_streak =
      (next_arm < AFL_BANDIT_MAX_ARMS) ? score_guard_streak_dbg[next_arm] : 0;
  if (!bandit->last_guard_streak && next_arm < bandit->num_arms) {
    bandit->last_guard_streak = bandit->arms[next_arm].guard_streak;
  }
  bandit->last_zp_streak =
      (next_arm < bandit->num_arms) ? bandit->arms[next_arm].zp_streak : 0;
  bandit->last_zp_factor =
      (next_arm < AFL_BANDIT_MAX_ARMS &&
       isfinite(score_zp_factor_dbg[next_arm]))
          ? score_zp_factor_dbg[next_arm]
          : 1.0;
  bandit->last_zp_applied =
      (next_arm < AFL_BANDIT_MAX_ARMS) ? score_zp_applied_dbg[next_arm] : 0;

  u8 next_mix_choice = 0;
  u32 next_arm_eff_candidate = next_arm;
  double next_a6_pi = 0.0;
  if (next_arm == BANDIT_ARM_A6) {
    u32 chosen = bandit->a6_topk[0];
    double chosen_prob = bandit->a6_topk_prob[0];
    double pick = (double)bandit_get_random(bandit) / 4294967296.0;
    if (!isfinite(pick) || pick < 0.0) pick = 0.0;
    if (pick > 1.0) pick = 1.0;
    double acc = 0.0;
    for (u32 k = 0; k < ADARARE_A6_TOPK && k < AFL_BANDIT_MAX_ARMS; ++k) {
      double p = bandit->a6_topk_prob[k];
      if (!isfinite(p) || p <= 0.0) continue;
      acc += p;
      if (pick <= acc) {
        chosen = bandit->a6_topk[k];
        chosen_prob = p;
        break;
      }
    }

    if (chosen >= bandit->num_arms || chosen == BANDIT_ARM_A6) {
      chosen = BANDIT_ARM_A1;
      if (chosen >= bandit->num_arms) chosen = 0;
      chosen_prob = bandit_a6_choice_prob(bandit, chosen);
    }

    if (!isfinite(chosen_prob) || chosen_prob <= 0.0) {
      chosen_prob = 1.0 / (double)ADARARE_A6_TOPK;
    }
    if (chosen_prob > 1.0) chosen_prob = 1.0;

    next_mix_choice = (u8)chosen;
    next_arm_eff_candidate = chosen;
    next_a6_pi = chosen_prob;
  }

  bandit->last_a6_choice = (next_arm == BANDIT_ARM_A6) ? next_arm_eff_candidate : next_arm;
  bandit->a6_choice_pi = next_a6_pi;

  bandit_dbg_log_window(
      bandit, entry_now_ms, cur_window_ms, win_total_ms, prev_arm_idx, next_arm,
      arm_weights,
      score_pred_dbg, score_bonus_dbg, score_total_dbg, score_guard_ratio_dbg,
      score_guard_factor_dbg, score_guard_streak_dbg, score_zp_factor_dbg,
      score_zp_applied_dbg, tie_break_hits, edges_rate,
      rarity_rate, edges_per_exec, rarity_per_exec,
      p90_edges, p90_rarity,
      scale_c1, scale_c2, res_arm, rw_gamma * thrpt_pen_eff,
      gate_factor, gate_bonus, gate_bonus_final, gate_bonus_eff, zero_prog_pen,
      has_progress,
      stag_bonus_boost, dwell_blocked, raw_reward,
      final_reward, raw_x, x, force_revisit);

  if (bandit->owner) {
    bandit->last_dict_attempts = bandit->owner->adarare_dict_attempts_win;
    bandit->last_dict_taken = bandit->owner->adarare_dict_taken_win;
    bandit->owner->adarare_dict_attempts_win = 0;
    bandit->owner->adarare_dict_taken_win = 0;
    bandit_log_window(bandit->owner);
  }

  /* Apply Selection */
  bandit->current_arm = next_arm;
  if (bandit->current_arm == prev_arm_idx) {
    if (bandit->dwell_windows < UINT_MAX) bandit->dwell_windows++;
  } else {
    bandit->dwell_windows = 0;
    bandit->last_selected_arm = bandit->current_arm;
  }
  bandit->mix_choice = next_mix_choice;
  bandit->current_arm_eff = next_arm_eff_candidate;
  if (bandit->current_arm != BANDIT_ARM_A6) {
    bandit->mix_choice = (u8)bandit->current_arm;
    bandit->current_arm_eff = bandit->current_arm;
    bandit->a6_choice_pi = 0.0;
  }

  bandit->current_arm_eff =
      bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  if (bandit->current_arm_eff >= bandit->num_arms) {
    bandit->current_arm_eff = BANDIT_ARM_A1;
  }

  /* Apply arm policy for NEXT window (dict, favored bias, energy multipliers). */
  bandit_apply_arm_policy(bandit->owner, bandit);

  /* Finalize Window Reset */
  bandit->win_new_cov = 0;
  bandit->win_new_bits = 0;
  bandit->win_clamp_hi = 0;
  bandit->win_guard_hits = 0;
  bandit->win_trend_active = 0;
  bandit->win_reward_zero = 0;
  bandit->win_novelty = 0.0;
  bandit->win_rarity_mass = 0.0;
  bandit->win_cmplog_progress = 0.0;
  bandit->win_cmplog_inject_count = 0;
  bandit->win_cmplog_inject_sum = 0.0;
  bandit->win_cmplog_inject_clipped_count = 0;
  bandit->win_rarity_samples = 0;
  bandit->win_path_len_sum = 0;
  bandit->win_execs = 0;
  bandit->win_time_us = 0;
  bandit->win_timeouts = 0;
  bandit->win_slow_execs = 0;
  bandit->win_gate_sum = 0.0;
  bandit->win_gate_samples = 0;
  bandit->win_gate_exec_sum = 0.0;
  bandit->win_gate_exec_samples = 0;
  bandit->tie_break_hits_win = 0;
  bandit->tie_break_det_hits_win = 0;
  memset(bandit->win_arm_ms, 0, sizeof(bandit->win_arm_ms));

  u64 end_now_us = get_cur_time_us();
  u64 end_now_ms = end_now_us / 1000;
  if (end_now_ms < entry_now_ms) end_now_ms = entry_now_ms;
  if (bandit->win_start_time > end_now_ms) {
      bandit->win_start_time = end_now_ms;
  }
  
  bandit->win_start_time = end_now_ms;
  bandit->win_last_ts = end_now_ms;
  bandit->win_last_arm = bandit->current_arm;
  
  bandit->arms[prev_arm_idx].last_selected_ms = entry_now_ms;

  bandit->last_rotate_us = end_now_us - rotate_start_us;
  bandit->rotate_us_total += bandit->last_rotate_us;
  bandit->rotate_count++;
  
  u32 rng_count_for_log = bandit->rng_log_idx;

  if (bandit->verify_enabled && bandit->verify_log_path) {
    if (!bandit->verify_fp) {
      bandit->verify_fp = fopen(bandit->verify_log_path, "a");
    }
    if (bandit->verify_fp) {
      /* Audit Hardening: Safe calc for visual logging */
      u64 win_actual_len = (entry_now_ms >= old_start_ms) ? (entry_now_ms - old_start_ms) : 0;
      u64 logic_shift_ms = (end_now_ms >= entry_now_ms) ? (end_now_ms - entry_now_ms) : 0;
      
      fprintf(bandit->verify_fp,
              "win_id=%llu entry_now_ms=%llu new_start_ms=%llu win_actual_len=%llu "
              "window_ms=%llu logic_shift_ms=%llu rotate_us=%llu rng_seeded_owner=%u "
              "rng_state=0x%llx rng_log_n=%u arm_prev=%u arm_next=%u "
              "inv_fail_win=%llu rad_cap_win=%llu score_cap_win=%llu\n",
              (unsigned long long)win_id, /* Explicit Window ID */
              (unsigned long long)entry_now_ms,
              (unsigned long long)bandit->win_start_time,
              (unsigned long long)win_actual_len, /* Checked Delta */
              (unsigned long long)bandit->window_ms,
              (unsigned long long)logic_shift_ms, /* Checked Shift */
              (unsigned long long)bandit->last_rotate_us, /* Added rotate_us */
              bandit->rng_seeded_from_owner,
              (unsigned long long)bandit->rng_state,
              rng_count_for_log, /* Fixed: uses cached value */
              prev_arm_idx, /* Added for audit */
              next_arm,     /* Added for audit */
              (unsigned long long)bandit->linucb_invert_fail_win,
              (unsigned long long)bandit->linucb_rad_cap_hits_win,
              (unsigned long long)bandit->linucb_score_cap_hits_win);
      fflush(bandit->verify_fp);
    }
  }

  bandit->rng_log_idx = 0;

  return 1;
}

u32 bandit_scale_score(bandit_state_t *bandit, u32 base_score, u32 cap) {
  if (!bandit || !bandit->enabled) { return base_score; }
  double multiplier = bandit_current_multiplier(bandit);
  double scaled = (double)base_score * multiplier;
  if (scaled < 1.0) { scaled = 1.0; }
  if (cap && scaled > (double)cap) { scaled = cap; }
  return (u32)scaled;
}

const char *bandit_reward_label(const bandit_state_t *bandit) {
  if (!bandit || !bandit->enabled) { return "off"; }
  switch (bandit->reward_mode) {
    case BANDIT_REWARD_BITS: return "bits";
    case BANDIT_REWARD_NOVELTY: return "novelty";
    case BANDIT_REWARD_RARITY_MASS: return "rarity_mass";
    case BANDIT_REWARD_EVENT:
    default: return "event";
  }
}

const char *bandit_reward_formula_label(const bandit_state_t *bandit) {
  if (!bandit || !bandit->enabled) { return "off"; }
  switch (bandit->reward_formula) {
    case BANDIT_REWARD_RATE: return "rate";
    case BANDIT_REWARD_RATE_COST:
    default: return "rate_cost";
  }
}

const char *bandit_gate_label(bandit_gate_t gate) {
  switch (gate) {
    case BANDIT_GATE_EXEC_US: return "exec_us";
    case BANDIT_GATE_PATH_LEN: return "path_len";
    case BANDIT_GATE_NONE:
    default: return "none";
  }
}

const char *bandit_arm_label(u32 arm) {
  const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm);
  if (cfg && cfg->name && cfg->name[0]) { return cfg->name; }
  switch (arm) {
    case BANDIT_ARM_A1: return "A1";
    case BANDIT_ARM_A2: return "A2";
    case BANDIT_ARM_A3: return "A3";
    case BANDIT_ARM_A4: return "A4";
    case BANDIT_ARM_A5: return "A5";
    case BANDIT_ARM_A6: return "A6";
    default: return "A?";
  }
}

double bandit_energy_boost(const bandit_state_t *bandit, double z_in) {
  if (!bandit || !bandit->enabled) { return 1.0; }
  double z = z_in;
  if (z < 0.0) z = 0.0;

  u32 arm = bandit->current_arm_eff;
  if (arm >= bandit->num_arms) {
    arm = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  }

  const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm);
  bandit_energy_mode_t mode =
      cfg ? cfg->energy_boost_mode : BANDIT_ENERGY_FLAT;

  double g = 0.0, cap = 1.0;
  switch (mode) {
    case BANDIT_ENERGY_LOG:
      g = 2.0 * log1p(2.0 * z);
      cap = 5.0;
      break;
    case BANDIT_ENERGY_LINEAR_SOFT:
      g = 0.5 * z;
      cap = 2.0;
      break;
    case BANDIT_ENERGY_LINEAR_MED:
      g = 1.0 * z;
      cap = 3.0;
      break;
    case BANDIT_ENERGY_THRESHOLD:
      g = (z >= 0.8) ? 2.0 * (z - 0.8) : 0.0;
      cap = 3.0;
      break;
    case BANDIT_ENERGY_FLAT:
    default:
      g = 0.0;
      cap = 1.0;
      break;
  }

  double boost = 1.0 + g;
  if (boost < 1.0) boost = 1.0;
  if (boost > cap) boost = cap;
  return boost;
}

u32 bandit_current_dict_prob(const bandit_state_t *bandit) {
  if (!bandit || !bandit->enabled) { return AFL_BANDIT_DICT_PROB_DEFAULT; }
  u32 arm = bandit->current_arm_eff;
  if (arm >= bandit->num_arms) {
    arm = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  }
  return bandit_dict_prob_for_arm(arm);
}

void bandit_score_sample_reset(bandit_state_t *bandit) {
  if (!bandit) return;
  reservoir_reset((bandit_reservoir_t*)bandit->score_res);
}

void bandit_score_sample_push(bandit_state_t *bandit, double score, u32 unused_external_rnd) {
  if (!bandit || !bandit->enabled) return;
  (void)unused_external_rnd;
  u32 r1 = bandit_get_random(bandit);
  u32 r2 = bandit_get_random(bandit);
  reservoir_add((bandit_reservoir_t*)bandit->score_res, score, r1, r2);
}

double bandit_score_sample_p90(bandit_state_t *bandit) {
    return reservoir_p90((bandit_reservoir_t*)bandit->score_res);
}

void bandit_set_log_dir(bandit_state_t *bandit, const char *out_dir) {
  if (!bandit) return;
  if (bandit->log_path) {
    ck_free(bandit->log_path);
    bandit->log_path = NULL;
  }
  const char *dir = (out_dir && out_dir[0]) ? out_dir : ".";
  bandit->log_path = alloc_printf("%s/.adarare_bandit.csv", dir);
}

void bandit_log_window(afl_state_t *afl) {
  if (!afl || !afl->bandit.enabled) return;
  if (!afl->is_main_node) return;

  bandit_state_t *b = &afl->bandit;
  const char *log_path = b->log_path && b->log_path[0]
                             ? (const char *)b->log_path
                             : NULL;
  if (b->verify_enabled && !b->verify_log_path) {
    const char *out_dir =
        (afl->out_dir && afl->out_dir[0]) ? (const char *)afl->out_dir : ".";
    b->verify_log_path = alloc_printf("%s/.adarare_verify.log", out_dir);
  }
  u8 path[PATH_MAX];
  if (!log_path) {
    const char *out_dir =
        (afl->out_dir && afl->out_dir[0]) ? (const char *)afl->out_dir : ".";
    snprintf((char *)path, sizeof(path), "%s/.adarare_bandit.csv", out_dir);
    log_path = (const char *)path;
  }

  if (!b->log_fp) {
    b->log_fp = fopen(log_path, "a+");
    if (!b->log_fp) return;
    struct stat st;
    if (fstat(fileno(b->log_fp), &st) == 0 && st.st_size > 0) {
      b->log_header_written = 1;
    }
  }

  if (!b->log_header_written) {
    fprintf(b->log_fp,
            "ts_ms,arm_id,arm_label,effective_arm,mix_choice,reward,edges_term,rarity_term,"
            "thrpt,thrpt_ref,thrpt_pen,thrpt_pen_eff,delta_bits,delta_rarity,timeout_hz,"
            "slow_hz,queued_paths,favored_ratio,p90_score,gate_factor,gate_bonus,"
            "gate_bonus_final,zero_prog_pen,has_progress,win_clamp_hi,win_guard_hits,win_trend_active,win_reward_zero,"
            "dwell_windows,dwell_blocked,guard_arm,guard_penalty,guard_streak,zp_streak,zp_factor,zp_applied,dict_prob,"
            "x_vc,x_vr,x_thrpt,x_q,x_pf,x_pto,ucb_score,base_raw,"
            "alpha,use_contextual,gate_mult,gate_cap,revisit_cooldown_ms,rarity_decay,"
            "rarity_ema,mix_p,a6_k0,a6_k1,a6_k2,a6_p0,a6_p1,a6_p2,a6_choice,a6_to_a1,a6_to_a2,a6_q1,a6_q2,a6_pi,a6_eta_eff,"
            "dict_attempts,dict_taken,dict_attempts_total,"
            "dict_taken_total,dict_enable,dict_baseline_prob,reward_alpha,"
            "reward_beta,reward_gamma,reward_c1,reward_c2,p90_valid,p90_n,"
            "linucb_invert_fail_last,linucb_rad_cap_hits_last,"
            "linucb_score_cap_hits_last,linucb_invert_fail_total,"
            "linucb_rad_cap_hits_total,linucb_score_cap_hits_total,"
            "cur_window_ms,time_sec,edges_rate,rarity_rate,edges_per_exec,rarity_per_exec,cmplog_rate,cmplog_term,tie_win,tie_total,a6_eta_stats,a6_eta_model,stag_bonus_boost,build_id,"
            "raw_x0,raw_x1,raw_x2,raw_x3,raw_x4,raw_x5,x0,x1,x2,x3,x4,x5,gate_bonus_eff,"
            "raw_reward_pre_cap,a6_pi_floor,dwell_emergency_zero,p90_add_edges,p90_add_rarity,discount,dyn_stag_thresh,"
            "in_warmup,warmup_target,warmup_min_pulls,gate_progress_gated,gate_bonus_headroom,gate_bonus_inject,tie_det_win,tie_det_total,tie_eps,"
            "a6_ips_w,a6_eff_arm,mix_p_used,mix_p_next,a6_sub_progress_ema,a6_sub_samples,"
            "reward_delta,scale_c3_used,p90_cmplog,cmplog_inject_count,cmplog_inject_sum,"
            "cmp_min_gain,cmp_win_clip,cmplog_inject_clipped_count,"
            "cmp_reward,cmp_producer_mode,cmp_a3_boost,cmplog_mod,cmp_rarity_lambda,"
            "cmplog_rate_ema,cmplog_rate_norm\n");
    b->log_header_written = 1;
  }

  u64 queued_paths = afl->queued_items;
  double favored_ratio = queued_paths ? ((double)afl->queued_favored / (double)queued_paths) : 0.0;
  const char *adarare_build_id = adarare_build_id_effective();
  
  u64 ts_ms = bandit_now_ms();

  fprintf(b->log_fp,
          "%llu,%u,%s,%u,%u,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,"
          "%0.0f,%0.4f,%0.6f,%0.6f,"
          "%llu,%0.4f,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%u,%u,%u,%u,%u,%u,%u,%u,%0.6f,%u,%u,%0.6f,%u,%u,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,"
          "%0.6f,%0.6f,"
          "%0.4f,%u,%0.4f,%0.4f,%llu,%0.4f,%0.4f,%0.4f,%u,%u,%u,%0.6f,%0.6f,%0.6f,%u,%llu,%llu,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%llu,%llu,%llu,%llu,%u,%u,"
          "%0.4f,%0.4f,%0.4f,%0.4f,%0.4f,%u,%llu,"
          "%llu,%llu,%llu,%llu,%llu,%llu,"
          "%llu,%0.4f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%llu,%llu,%0.6f,%0.6f,%u,%s,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,"
          "%0.6f,%0.6f,%u,%u,%u,%0.6f,%u,%u,%0.6f,%0.6f,%u,%0.6f,%0.6f,%llu,%llu,%0.6f,%0.6f,%u,%0.6f,%0.6f,%0.6f,%llu,%0.6f,%0.6f,%0.6f,%llu,%0.6f,%0.6f,%0.6f,%llu,%u,%u,%u,%0.6f,%0.6f",
          (unsigned long long)ts_ms, b->last_arm_used,
          bandit_arm_label(b->last_arm_used), b->last_arm_eff_used,
          b->last_mix_choice,
          b->last_reward, b->last_edges_term, b->last_rarity_term, 
          b->last_thrpt, b->last_thrpt_ref, b->last_thrpt_pen,
          b->last_thrpt_pen_eff,
          b->last_delta_bits, b->last_delta_rarity, b->last_timeout_hz, b->last_slow_hz,
          (unsigned long long)queued_paths, favored_ratio, b->last_p90_score,
          b->last_gate_factor, b->last_gate_bonus, b->last_gate_bonus_final,
          b->last_zero_prog_pen,
          (unsigned int)b->last_win_has_progress, b->last_win_clamp_hi,
          b->last_win_guard_hits, (unsigned int)b->last_win_trend_active,
          (unsigned int)b->last_win_reward_zero, b->dwell_windows,
          (unsigned int)b->last_dwell_blocked, b->last_guard_arm,
          b->last_guard_penalty, b->last_guard_streak, b->last_zp_streak,
          b->last_zp_factor, (unsigned int)b->last_zp_applied,
          b->last_dict_prob,
          b->last_x[0], b->last_x[1],
          b->last_x[2], b->last_x[3], b->last_x[4], b->last_x[5],
          b->last_ucb_score, b->last_base_raw,
          b->alpha, (unsigned int)b->use_contextual, b->gate_multiplier,
          b->gate_cap, (unsigned long long)b->revisit_time_ms,
          b->rarity_decay, b->rarity_ema, b->mix_p,
          b->a6_topk[0], b->a6_topk[1], b->a6_topk[2], b->a6_topk_prob[0],
          b->a6_topk_prob[1], b->a6_topk_prob[2], b->last_a6_choice,
          (unsigned long long)b->a6_to_a1, (unsigned long long)b->a6_to_a2,
          b->a6_q1, b->a6_q2, b->last_a6_pi_eff, b->last_a6_eta_eff,
          (unsigned long long)b->last_dict_attempts,
          (unsigned long long)b->last_dict_taken,
          (unsigned long long)afl->adarare_dict_attempts_total,
          (unsigned long long)afl->adarare_dict_taken_total, b->dict_enable,
          b->dict_baseline_prob, b->reward_alpha, b->reward_beta,
          b->reward_gamma, b->reward_c1, b->reward_c2, b->last_p90_valid,
          (unsigned long long)b->last_p90_n, (unsigned long long)b->linucb_invert_fail_last,
          (unsigned long long)b->linucb_rad_cap_hits_last,
          (unsigned long long)b->linucb_score_cap_hits_last,
          (unsigned long long)b->linucb_invert_fail_total,
          (unsigned long long)b->linucb_rad_cap_hits_total,
          (unsigned long long)b->linucb_score_cap_hits_total,
          (unsigned long long)b->last_cur_window_ms, b->last_time_sec,
          b->last_edges_rate, b->last_rarity_rate,
          b->last_edges_per_exec, b->last_rarity_per_exec,
          b->last_cmplog_rate, b->last_cmplog_term,
          (unsigned long long)b->tie_break_hits_win,
          (unsigned long long)b->tie_break_hits_total,
          b->last_a6_eta_stats, b->last_a6_eta_model,
          (unsigned int)b->last_stag_bonus_boost, adarare_build_id,
          b->last_raw_x[0], b->last_raw_x[1], b->last_raw_x[2], b->last_raw_x[3],
          b->last_raw_x[4], b->last_raw_x[5], b->last_x[0], b->last_x[1],
          b->last_x[2], b->last_x[3], b->last_x[4], b->last_x[5],
          b->last_gate_bonus_eff, b->last_raw_reward_pre_cap,
          b->last_a6_pi_floor, (unsigned int)b->last_dwell_emergency_zero,
          (unsigned int)b->last_p90_add_edges,
          (unsigned int)b->last_p90_add_rarity, b->discount,
          b->last_dyn_stag_thresh,
          (unsigned int)b->in_warmup, b->warmup_pulls_target,
          b->last_warmup_min_pulls, (unsigned int)b->last_gate_progress_gated,
          b->last_gate_bonus_headroom, b->last_gate_bonus_inject,
          (unsigned long long)b->tie_break_det_hits_win,
          (unsigned long long)b->tie_break_det_hits_total, b->last_tie_eps,
          b->last_a6_ips_w, b->last_a6_eff_arm, b->last_mix_p_used,
          b->last_mix_p_next, b->a6_sub_progress_ema,
          (unsigned long long)b->a6_sub_samples, b->last_reward_delta_used,
          b->last_scale_c3_used, b->last_p90_cmplog,
          (unsigned long long)b->last_cmplog_inject_count,
          b->last_cmplog_inject_sum, b->cmp_min_gain, b->cmp_win_clip,
          (unsigned long long)b->last_cmplog_inject_clipped_count,
          (unsigned int)b->cmp_reward, (unsigned int)b->cmp_producer_mode,
          (unsigned int)b->cmp_a3_boost, b->last_cmplog_mod,
          b->cmp_rarity_lambda);

  fprintf(b->log_fp, ",%0.6f,%0.6f\n", b->cmplog_rate_ema,
          b->last_cmplog_rate_norm);

  fflush(b->log_fp);
}

void adarare_write_config_snapshot(afl_state_t *afl) {
  if (!afl || !afl->out_dir || !afl->is_main_node) { return; }

  bandit_state_t *b = &afl->bandit;
  if (b->config_written) return;

  char *final_path = alloc_printf("%s/.adarare_config.json", afl->out_dir);
  if (!final_path) return;

  struct stat st;
  if (stat(final_path, &st) == 0) {
    b->config_written = 1;
    ck_free(final_path);
    return;
  }

  char *tmp_template = alloc_printf("%s/.adarare_config.tmpXXXXXX", afl->out_dir);
  if (!tmp_template) {
    ck_free(final_path);
    return;
  }

  int fd = mkstemp(tmp_template);
  if (fd < 0) {
    ck_free(tmp_template);
    ck_free(final_path);
    return;
  }

  FILE *fp = fdopen(fd, "w");
  if (!fp) {
    close(fd);
    unlink(tmp_template);
    ck_free(tmp_template);
    ck_free(final_path);
    return;
  }

  const char *log_path = b->log_path ? (const char *)b->log_path : "";
  const char *build_id = afl->build_id[0] ? (const char *)afl->build_id : "unknown";
  const char *adarare_build_id = adarare_build_id_effective();
  const char *a6_offpolicy_mode_label =
      bandit_a6_offpolicy_mode_label((u8)b->a6_offpolicy_mode);
  u8 per_arm_w_delta_active = 0;
  for (u32 arm = 0; arm < AFL_BANDIT_MAX_ARMS; ++arm) {
    const bandit_arm_cfg_t *cfg = bandit_arm_cfg_for_arm(arm);
    if (cfg && isfinite(cfg->w_delta) && cfg->w_delta > 0.0 &&
        (arm != BANDIT_ARM_A3 || b->cmp_a3_boost)) {
      per_arm_w_delta_active = 1;
      break;
    }
  }

  fprintf(fp,
          "{\n"
          "  \"enabled\": %u,\n"
          "  \"window_ms\": %llu,\n"
          "  \"num_arms\": %u,\n"
          "  \"arm_labels\": [\"A1\",\"A2\",\"A3\",\"A4\",\"A5\",\"A6\"],\n"
          "  \"contextual\": %u,\n"
          "  \"pid\": %u,\n"
          "  \"alpha\": %.4f,\n"
          "  \"ridge_lambda\": %.4f,\n"
          "  \"gate_mult\": %.4f,\n"
          "  \"gate_cap\": %.4f,\n"
          "  \"revisit_cooldown_ms\": %llu,\n"
          "  \"rarity_decay\": %.4f,\n"
          "  \"rarity_ema\": %.4f,\n"
          "  \"mix_p\": %.4f,\n"
          "  \"a6_offpolicy_mode\": ",
          b->enabled, (unsigned long long)b->window_ms, b->num_arms,
          b->use_contextual, (unsigned int)getpid(), b->alpha, b->ridge_lambda, b->gate_multiplier,
          b->gate_cap, (unsigned long long)b->revisit_time_ms,
          b->rarity_decay, b->rarity_ema, b->mix_p);
  json_print_escaped(fp, a6_offpolicy_mode_label);
  fprintf(fp,
          ",\n"
          "  \"a6_pi\": %.6f,\n"
          "  \"a6_ips_w\": %.6f,\n"
          "  \"a6_eff_arm\": %u,\n"
          "  \"mix_p_used\": %.6f,\n"
          "  \"mix_p_next\": %.6f,\n"
          "  \"a6_sub_progress_ema\": %.6f,\n"
          "  \"a6_sub_samples\": %llu,\n"
          "  \"dict_enable\": %u,\n"
          "  \"dict_baseline_prob\": %u,\n"
          "  \"per_arm_w_delta_support\": 1,\n"
          "  \"per_arm_w_delta_active\": %u,\n"
          "  \"default_reward_delta\": %.4f,\n"
          "  \"default_reward_c3\": %.4f,\n"
          "  \"reward_alpha\": %.4f,\n"
          "  \"reward_beta\": %.4f,\n"
          "  \"reward_gamma\": %.4f,\n"
          "  \"reward_delta\": %.4f,\n"
          "  \"reward_c1\": %.4f,\n"
          "  \"reward_c2\": %.4f,\n"
          "  \"reward_c3\": %.4f,\n"
          "  \"cmp_min_gain\": %.6f,\n"
          "  \"cmp_win_clip\": %.6f,\n"
          "  \"cmp_rarity_lambda\": %.6f,\n"
          "  \"cmp_baseline_norm\": %u,\n"
          "  \"cmp_baseline_ema\": %.6f,\n"
          "  \"cmp_one_shot_site\": %u,\n"
          "  \"cmp_reward\": %u,\n"
          "  \"cmp_producer_mode\": %u,\n"
          "  \"cmp_a3_boost\": %u,\n"
          "  \"warmup_pulls_target\": %.4f,\n"
          "  \"progress_gate_enabled\": 1,\n"
          "  \"gate_headroom_injection\": 1,\n"
          "  \"tie_break_deterministic\": 1,\n"
          "  \"tie_eps_rel\": %.6f,\n"
          "  \"score_sample_n\": %u,\n"
          "  \"p90_min_samples\": %u,\n"
          "  \"log_path\": ",
          b->last_a6_pi_eff, b->last_a6_ips_w, b->last_a6_eff_arm,
          b->last_mix_p_used, b->last_mix_p_next, b->a6_sub_progress_ema,
          (unsigned long long)b->a6_sub_samples, b->dict_enable,
          b->dict_baseline_prob, (unsigned int)per_arm_w_delta_active,
          b->reward_delta, b->reward_c3, b->reward_alpha, b->reward_beta,
          b->reward_gamma, b->reward_delta, b->reward_c1, b->reward_c2,
          b->reward_c3, b->cmp_min_gain, b->cmp_win_clip, b->cmp_rarity_lambda,
          (unsigned int)b->cmp_baseline_norm, b->cmp_baseline_ema,
          (unsigned int)b->cmp_one_shot_site, (unsigned int)b->cmp_reward,
          (unsigned int)b->cmp_producer_mode, (unsigned int)b->cmp_a3_boost,
          b->warmup_pulls_target, ADARARE_TIE_EPS_REL, BANDIT_SCORE_SAMPLE_N,
          BANDIT_P90_MIN_SAMPLES);

  json_print_escaped(fp, log_path);
  fprintf(fp, ",\n  \"adarare_build_id\": ");
  json_print_escaped(fp, adarare_build_id);
  fprintf(fp, ",\n  \"build_id\": ");
  json_print_escaped(fp, build_id);
  fprintf(fp, ",\n  \"afl_version\": ");
  json_print_escaped(fp, VERSION);
  fprintf(fp, "\n}\n");

  fflush(fp);
  fsync(fd);
  
  fclose(fp);
  if (rename(tmp_template, final_path) == 0) {
    b->config_written = 1;
  } else {
    unlink(tmp_template);
  }

  ck_free(tmp_template);
  ck_free(final_path);
}
