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
#define BANDIT_P90_MIN_SAMPLES 64

/* Normalization Sensitivity */
#define BANDIT_LOG_SCALE_FACTOR 0.2 

/* Gate Bonus: 5% boost per log-unit of gate value */
#define BANDIT_GATE_MULTIPLIER 0.08
#define BANDIT_GATE_CAP 1.5

/* Explicit Revisit Policy: 30 minutes default. */
#define BANDIT_REVISIT_TIME_MS (10ULL * 60ULL * 1000ULL)

/* Revisit Score (Case B) */
#define BANDIT_REVISIT_SCORE 1.4

/* Safety Constraints */
#define BANDIT_PULLS_EPSILON 1e-6
#define BANDIT_BONUS_CAP 2.0

/* Keep interval comfortably above BANDIT_P90_MIN_SAMPLES so P90 scaling stays active. */
#define BANDIT_RESCALE_INTERVAL 360

#define BANDIT_MATRIX_VAL_CAP 1.0e12
#define BANDIT_MATRIX_RESCALE_FACTOR 1.0e-6 /* Keep scaled entries in same order
                                               as ridge_lambda magnitude after
                                               rescale; diagonal is clamped to
                                               ridge_lambda to keep conditioning. */
/* Keep ETA at 1.0 unless selections accounting is redesigned for fractional credit. */
#define BANDIT_A6_OFFPOLICY_ETA 1.0

/* --- Helper Structures --- */

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

static inline u32 bandit_default_arm_count(void) { return 6; }

static inline double bandit_multiplier_for_arm(u32 arm_idx) {
  (void)arm_idx;
  return 1.0;
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

static u32 bandit_get_random(bandit_state_t *bandit) {
  if (!bandit) { return (u32)(get_cur_time_us() >> 32); }
  if (!bandit->rng_state) bandit->rng_state = 1;
  u32 val = (u32)(xorshift64(&bandit->rng_state) >> 32);
  if (bandit->verify_enabled && bandit->rng_log_idx < 32) {
    bandit->rng_log[bandit->rng_log_idx++] = val;
  }
  return val;
}

static const u32 bandit_dict_probs[] = {0, 10, 20, 30, 0, 10};

static inline u32 bandit_effective_arm(u32 arm, u8 mix_choice) {

  if (arm == BANDIT_ARM_A6) {
    return mix_choice ? BANDIT_ARM_A2 : BANDIT_ARM_A1;
  }

  return arm;

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
  u32 max_idx = (u32)(sizeof(bandit_dict_probs) / sizeof(bandit_dict_probs[0]));
  if (arm_idx >= max_idx) { return bandit_dict_probs[max_idx - 1]; }
  return bandit_dict_probs[arm_idx];
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
  
  if (bandit->log_fp) { fclose(bandit->log_fp); }
  if (bandit->log_path) { ck_free(bandit->log_path); }
  if (bandit->verify_fp) { fclose(bandit->verify_fp); }
  if (bandit->verify_log_path) { ck_free(bandit->verify_log_path); }
  if (bandit->score_res) ck_free(bandit->score_res);
  if (bandit->edges_rate_res) ck_free(bandit->edges_rate_res);
  if (bandit->rarity_rate_res) ck_free(bandit->rarity_rate_res);
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
  bandit->rng_state = 0;
  bandit->verify_enabled =
      bandit_env_int("AFL_ADARARE_VERIFY", 0, 0, 1) ? 1 : 0;
  bandit->rng_seeded_from_owner = 0;
  bandit->rng_log_idx = 0;
  bandit->window_ms = window_ms;
  
  /* Initial Start Time */
  bandit->win_start_time = bandit_now_ms();
  
  bandit->total_rounds = 0.0;     
  bandit->total_selections = 0;   
  
  bandit->last_win_gate = 1.0;
  bandit->last_win_gate_execavg = 1.0;
  bandit->last_raw_reward = 0.0;
  bandit->last_gate_factor = 1.0;
  
  bandit->rarity_norm = BANDIT_RARITY_NORM_PATH_LEN;
  bandit->discount = 0.99; 
  bandit->warmup_windows = 20; 
  bandit->in_warmup = 1;
  bandit->mix_choice = 0;
  bandit->last_mix_choice = 0;
  bandit->last_arm_used = 0;
  bandit->last_arm_eff_used = 0;
  bandit->alpha = 0.5;
  bandit->use_contextual = 1;
  bandit->ridge_lambda =
      bandit_env_double("AFL_ADARARE_RIDGE", BANDIT_LINUCB_RIDGE, 1.0, 1000.0);
  bandit->gate_multiplier = bandit_env_double("AFL_ADARARE_GATE_MULT",
                                              BANDIT_GATE_MULTIPLIER, 0.0, 1.0);
  bandit->gate_cap =
      bandit_env_double("AFL_ADARARE_GATE_CAP", BANDIT_GATE_CAP, 1.0, 10.0);
  bandit->revisit_time_ms = bandit_env_u64(
      "AFL_ADARARE_REVISIT_MS", BANDIT_REVISIT_TIME_MS, 60ULL * 1000ULL,
      24ULL * 60ULL * 60ULL * 1000ULL);
  bandit->rarity_decay = bandit_env_double("AFL_ADARARE_SCORE_DECAY",
                                           BANDIT_DEFAULT_RARITY_DECAY, 0.90,
                                           1.0);
  bandit->rarity_ema =
      bandit_env_double("AFL_ADARARE_RARITY_EMA", 1.0, 0.05, 1.0);
  bandit->mix_p = bandit_env_double("AFL_ADARARE_MIX_P", 0.5, 0.0, 1.0);
  bandit->dict_baseline_prob =
      (u32)bandit_env_u64("AFL_ADARARE_DICT_BASELINE_PROB", 100, 0, 100);
  bandit->dict_enable =
      bandit_env_int("AFL_ADARARE_DICT_ENABLE", 1, 0, 1) ? 1 : 0;
  bandit->reward_alpha =
      bandit_env_double("AFL_ADARARE_REWARD_ALPHA", 0.6, 0.0, 1.0);
  bandit->reward_beta =
      bandit_env_double("AFL_ADARARE_REWARD_BETA", 0.3, 0.0, 1.0);
  bandit->reward_gamma =
      bandit_env_double("AFL_ADARARE_REWARD_GAMMA", 0.1, 0.0, 1.0);
      
  bandit->reward_c1 =
      bandit_env_double("AFL_ADARARE_REWARD_C1", 50.0, 1e-12, 1e12);
  bandit->reward_c2 =
      bandit_env_double("AFL_ADARARE_REWARD_C2", 5.0, 1e-12, 1e12);
      
  double wsum = bandit->reward_alpha + bandit->reward_beta + bandit->reward_gamma;
  if (wsum <= 0.0) {
    bandit->reward_alpha = 0.6;
    bandit->reward_beta = 0.3;
    bandit->reward_gamma = 0.1;
  }
  bandit->alpha =
      bandit_env_double("AFL_ADARARE_ALPHA", bandit->alpha, 0.0, 10.0);
  bandit->use_contextual =
      bandit_env_int("AFL_ADARARE_CONTEXTUAL", 1, 0, 1) ? 1 : 0;
      
  bandit->last_p90_score = 1.0;
  bandit->last_p90_n = 0;
  bandit->last_p90_valid = 0;
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
  bandit->last_edges_term = 0.0;
  bandit->last_rarity_term = 0.0;
  
  bandit->linucb_invert_fail_last = 0;
  bandit->linucb_rad_cap_hits_last = 0;
  bandit->linucb_score_cap_hits_last = 0;

  for (u32 i = 0; i < bandit->num_arms; ++i) {
    for (u32 r = 0; r < BANDIT_CTX_DIM; ++r) {
      for (u32 c = 0; c < BANDIT_CTX_DIM; ++c) {
        bandit->arms[i].A[r][c] = (r == c) ? bandit->ridge_lambda : 0.0;
      }
      bandit->arms[i].b[r] = 0.0;
    }
    bandit->arms[i].last_selected_ms = 0;
  }
  for (u32 k = 0; k < BANDIT_CTX_DIM; ++k) bandit->last_x[k] = 0.0;
  
  bandit->score_res = ck_alloc(sizeof(bandit_reservoir_t));
  bandit->edges_rate_res = ck_alloc(sizeof(bandit_reservoir_t));
  bandit->rarity_rate_res = ck_alloc(sizeof(bandit_reservoir_t));
  
  if (!bandit->score_res || !bandit->edges_rate_res || !bandit->rarity_rate_res) {
      bandit_deinit(bandit);
      return; 
  }

  reservoir_reset((bandit_reservoir_t*)bandit->score_res);
  reservoir_reset((bandit_reservoir_t*)bandit->edges_rate_res);
  reservoir_reset((bandit_reservoir_t*)bandit->rarity_rate_res);
}

void bandit_set_owner(bandit_state_t *bandit, struct afl_state *afl) {
  if (!bandit) return;
  bandit->owner = afl;
  if (afl) {
    afl->bandit_dict_enable = bandit->dict_enable ? 1 : 0;
    afl->adarare_dict_prob = bandit_current_dict_prob(bandit);
    if (!bandit->enabled) {
      afl->adarare_dict_prob = bandit->dict_baseline_prob;
    }
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

double bandit_current_multiplier(const bandit_state_t *bandit) {
  if (!bandit || !bandit->enabled) { return 1.0; }
  return bandit_multiplier_for_arm(bandit->current_arm);
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
  
  if (entry_now_ms - bandit->win_start_time < bandit->window_ms) { return 0; }
  
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
  
  bandit->in_warmup = bandit->rotate_count < bandit->warmup_windows;

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
  
  double win_sec_fallback = (double)bandit->window_ms / 1000.0;
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
  /* 2. Gate Bonus (Plumbed into Rates)                           */
  /* ============================================================ */
  
  double avg_gate = 0.0;
  if (bandit->win_gate_exec_samples > 0) {
      avg_gate = bandit->win_gate_exec_sum / bandit->win_gate_exec_samples;
  } else if (bandit->win_gate_samples > 0) {
      avg_gate = bandit->win_gate_sum / bandit->win_gate_samples;
  }

  double gate_factor = 1.0;
  if (avg_gate > 0.0) {
      gate_factor = 1.0 + (bandit_log_compress(avg_gate) * bandit->gate_multiplier);
      if (gate_factor > bandit->gate_cap) gate_factor = bandit->gate_cap;
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

  double edges_rate = delta_bits / safe_time;
  double rarity_rate = delta_rarity / safe_time;
  
  edges_rate *= gate_factor;
  rarity_rate *= gate_factor;

  u32 r1 = bandit_get_random(bandit);
  u32 r2 = bandit_get_random(bandit);
  u32 r3 = bandit_get_random(bandit);
  u32 r4 = bandit_get_random(bandit);

  bandit_reservoir_t *edges_res = (bandit_reservoir_t*)bandit->edges_rate_res;
  bandit_reservoir_t *rarity_res = (bandit_reservoir_t*)bandit->rarity_rate_res;

  reservoir_add(edges_res, edges_rate, r1, r2);
  reservoir_add(rarity_res, rarity_rate, r3, r4);

  double p90_edges = reservoir_p90(edges_res);
  double p90_rarity = reservoir_p90(rarity_res);

  double scale_c1 = bandit->reward_c1;
  double scale_c2 = bandit->reward_c2;

  if (!bandit->in_warmup && edges_res->count >= BANDIT_P90_MIN_SAMPLES && p90_edges > 1e-6) scale_c1 = p90_edges;
  if (!bandit->in_warmup && rarity_res->count >= BANDIT_P90_MIN_SAMPLES && p90_rarity > 1e-6) scale_c2 = p90_rarity;

  double edges_term = tanh(edges_rate / scale_c1);
  double rarity_term = tanh(rarity_rate / scale_c2);
  
  double raw_reward = bandit->reward_alpha * edges_term +
                      bandit->reward_beta * rarity_term -
                      bandit->reward_gamma * thrpt_pen;
  
  if (raw_reward < 0.0) raw_reward = 0.0;
  if (raw_reward > 1.0) raw_reward = 1.0;
  if (!isfinite(raw_reward)) raw_reward = 0.0;

  double timeout_hz = (double)bandit->win_timeouts / safe_time;
  double slow_hz = (double)bandit->win_slow_execs / safe_time;

  bandit->last_thrpt = thrpt;
  bandit->last_thrpt_ref = bandit->thrpt_ref_inited ? bandit->thrpt_ref_ema : thrpt;
  bandit->last_thrpt_pen = thrpt_pen;
  bandit->last_timeout_hz = timeout_hz;
  bandit->last_slow_hz = slow_hz;
  bandit->last_delta_bits = delta_bits;
  bandit->last_delta_rarity = delta_rarity;
  bandit->last_gate_factor = gate_factor;
  
  bandit->last_time_sec = safe_time;
  bandit->last_edges_rate = edges_rate;
  bandit->last_rarity_rate = rarity_rate;
  bandit->last_edges_term = edges_term;
  bandit->last_rarity_term = rarity_term;

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

  current->pulls += 1.0; 
  current->total_reward += final_reward;
  current->selections++;
  
  bandit->total_rounds += 1.0;
  bandit->total_selections++;  
  
  current->last_selected_round = bandit->total_selections; 
  /* Note: last_selected_ms will be updated at end using Entry Time (for Revisit consistency) */
  
  bandit->last_arm_used = bandit->current_arm;
  bandit->last_arm_eff_used = window_arm_eff;
  bandit->last_mix_choice = bandit->mix_choice;
  bandit->last_reward = final_reward; 
  bandit->last_raw_reward = raw_reward;   
  
  bandit->last_win_execs       = bandit->win_execs;
  bandit->last_win_time_us     = bandit->win_time_us;
  bandit->last_win_new_cov     = bandit->win_new_cov;
  bandit->last_win_new_bits    = bandit->win_new_bits;
  bandit->last_win_novelty     = bandit->win_novelty;
  bandit->last_win_rarity_mass = bandit->win_rarity_mass;
  bandit->last_win_timeouts    = bandit->win_timeouts;
  bandit->last_win_slow_execs  = bandit->win_slow_execs;
  
  bandit->last_win_gate = bandit->win_gate_samples 
      ? bandit->win_gate_sum / bandit->win_gate_samples : 0.0;
  bandit->last_win_gate_execavg = bandit->win_gate_exec_samples 
      ? bandit->win_gate_exec_sum / bandit->win_gate_exec_samples : 0.0;
      
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

  if (bandit->owner) {
    bandit->last_dict_attempts = bandit->owner->adarare_dict_attempts_win;
    bandit->last_dict_taken = bandit->owner->adarare_dict_taken_win;
    bandit->owner->adarare_dict_attempts_win = 0;
    bandit->owner->adarare_dict_taken_win = 0;
    bandit_log_window(bandit->owner);
  }

  /* ============================================================ */
  /* 5. Selection (Time-Consistent Revisit)                       */
  /* ============================================================ */

  u32 next_arm = bandit->current_arm;
  
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

  x[0] = log1p(vc) * 0.20;
  x[1] = log1p(vr) * 0.50;
  x[2] = log1p(thrpt_ctx) * 0.20;
  x[3] = log1p(q_rel) * 1.0;
  x[4] = favored_ratio * 2.0;
  x[5] = log1p(p_timeout) * 1.0;
  for (int k = 0; k < BANDIT_CTX_DIM; ++k) {
    if (!isfinite(x[k]) || x[k] < 0.0) x[k] = 0.0;
    if (x[k] > 3.0) x[k] = 3.0;
    bandit->last_x[k] = x[k];
  }

  if (bandit->use_contextual) {
    bandit_update_arm_model(bandit, current, x, final_reward, 1.0);
  }

  if (bandit->current_arm == BANDIT_ARM_A6 && window_arm_eff < bandit->num_arms &&
      window_arm_eff != bandit->current_arm) {
    bandit_arm_state_t *eff_arm = &bandit->arms[window_arm_eff];
    eff_arm->pulls += BANDIT_A6_OFFPOLICY_ETA;
    eff_arm->total_reward += final_reward * BANDIT_A6_OFFPOLICY_ETA;
    if (BANDIT_A6_OFFPOLICY_ETA > 0.0) {
      eff_arm->selections += 1;
      eff_arm->last_selected_round = bandit->total_selections;
    }
    if (bandit->use_contextual) {
      bandit_update_arm_model(bandit, eff_arm, x, final_reward,
                              BANDIT_A6_OFFPOLICY_ETA);
    }
  }

  if (bandit->in_warmup) {
    next_arm = (bandit->current_arm + 1) % bandit->num_arms;
  } else {
    double best_score = -DBL_MAX;
    double log_t = log((double)(bandit->total_selections > 1 ? bandit->total_selections : 1));

    for (u32 i = 0; i < bandit->num_arms; ++i) {
      double score;
      
      if (bandit->arms[i].selections > 0 && bandit->arms[i].last_selected_ms == 0) {
          bandit->arms[i].last_selected_ms = entry_now_ms;
      }
      
      u64 ms_since = 0;
      if (bandit->arms[i].selections > 0) {
          if (entry_now_ms >= bandit->arms[i].last_selected_ms) {
              ms_since = entry_now_ms - bandit->arms[i].last_selected_ms;
          } else {
              ms_since = 0;
          }
      }

      if (bandit->arms[i].selections == 0) {
        score = 1e9;
      } else if (ms_since > bandit->revisit_time_ms) {
        score = BANDIT_REVISIT_SCORE;
      } else if (bandit->use_contextual) {
        double Ainv[BANDIT_CTX_DIM][BANDIT_CTX_DIM];
        if (!invert6((const double(*)[BANDIT_CTX_DIM])bandit->arms[i].A, Ainv)) {
          bandit->linucb_invert_fail_win++;
          bandit->linucb_invert_fail_total++;
          double pulls = bandit->arms[i].pulls;
          if (pulls < BANDIT_PULLS_EPSILON) pulls = BANDIT_PULLS_EPSILON;
          double mean = bandit->arms[i].total_reward / pulls;
          double bonus = sqrt((2.0 * log_t) / pulls);
          if (bonus > BANDIT_BONUS_CAP) bonus = BANDIT_BONUS_CAP;
          score = mean + bonus;
        } else {
          double theta[BANDIT_CTX_DIM] = {0};
          for (int r = 0; r < BANDIT_CTX_DIM; ++r) {
            for (int c = 0; c < BANDIT_CTX_DIM; ++c) {
              theta[r] += Ainv[r][c] * bandit->arms[i].b[c];
            }
          }
          double mean = 0.0;
          for (int k = 0; k < BANDIT_CTX_DIM; ++k) mean += theta[k] * x[k];
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
          score = mean + bandit->alpha * rad;
          if (score < 0.0) score = 0.0; 
          
          if (!isfinite(score)) score = 0.0;
          if (score > 5.0) {
            bandit->linucb_score_cap_hits_win++;
            bandit->linucb_score_cap_hits_total++;
            score = 5.0;
          }
        }
      } else {
        double pulls = bandit->arms[i].pulls;
        if (pulls < BANDIT_PULLS_EPSILON) pulls = BANDIT_PULLS_EPSILON;
        double mean = bandit->arms[i].total_reward / pulls;
        if (mean < 0.0) mean = 0.0;
        if (mean > 1.0) mean = 1.0;
        double bonus = sqrt((2.0 * log_t) / pulls);
        if (bonus > BANDIT_BONUS_CAP) bonus = BANDIT_BONUS_CAP;
        score = mean + bonus;
      }

      if (score > best_score) {
        best_score = score;
        next_arm = i;
        bandit->last_ucb_score = score;
      }
    }
  }

  /* Apply Selection */
  bandit->current_arm = next_arm;
  bandit->mix_choice = 0;
  
  if (bandit->current_arm == BANDIT_ARM_A6) {
    u32 r = bandit_get_random(bandit);
    double p = bandit->mix_p;
    if (p < 0.0) p = 0.0;
    if (p > 1.0) p = 1.0;
    const double N = 4294967296.0; 
    u64 threshold = (u64)(p * N); 
    bandit->mix_choice = ((u64)r < threshold) ? 0 : 1;
  }

  bandit->current_arm_eff = bandit_effective_arm(bandit->current_arm, bandit->mix_choice);
  if (bandit->current_arm_eff >= bandit->num_arms) {
    bandit->current_arm_eff = BANDIT_ARM_A1;
  }

  /* Update dict prob for NEXT window (frozen). */
  u32 next_arm_eff = bandit->current_arm_eff;
  
  u32 next_dict_prob = bandit->dict_enable ? bandit_dict_prob_for_arm(next_arm_eff)
                                           : bandit->dict_baseline_prob;
  
  bandit->last_dict_prob = next_dict_prob;
                                               
  if (bandit->owner) { 
      bandit->owner->adarare_dict_prob = next_dict_prob;
  }

  /* Finalize Window Reset */
  bandit->win_new_cov = 0;
  bandit->win_new_bits = 0;
  bandit->win_novelty = 0.0;
  bandit->win_rarity_mass = 0.0;
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

  u64 end_now_us = get_cur_time_us();
  u64 end_now_ms = end_now_us / 1000;
  if (end_now_ms < entry_now_ms) end_now_ms = entry_now_ms;
  if (bandit->win_start_time > end_now_ms) {
      bandit->win_start_time = end_now_ms;
  }
  
  bandit->win_start_time = end_now_ms;
  
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

  double g = 0.0, cap = 1.0;
  switch (arm) {
    case BANDIT_ARM_A1:
      g = 2.0 * log1p(2.0 * z);
      cap = 5.0;
      break;
    case BANDIT_ARM_A2:
      g = 0.5 * z;
      cap = 2.0;
      break;
    case BANDIT_ARM_A3:
      g = 1.0 * z;
      cap = 3.0;
      break;
    case BANDIT_ARM_A4:
      if (z >= 0.8) {
        g = 2.0 * (z - 0.8);
      } else {
        g = 0.0;
      }
      cap = 3.0;
      break;
    case BANDIT_ARM_A5:
      g = 0.0;
      cap = 1.0;
      break;
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
            "thrpt,thrpt_ref,thrpt_pen,delta_bits,delta_rarity,timeout_hz,"
            "slow_hz,queued_paths,favored_ratio,p90_score,gate_factor,dict_prob,"
            "x_vc,x_vr,x_thrpt,x_q,x_pf,x_pto,ucb_score,base_raw,"
            "alpha,use_contextual,gate_mult,gate_cap,revisit_ms,rarity_decay,"
            "rarity_ema,mix_p,dict_attempts,dict_taken,dict_attempts_total,"
            "dict_taken_total,dict_enable,dict_baseline_prob,reward_alpha,"
            "reward_beta,reward_gamma,reward_c1,reward_c2,p90_valid,p90_n,"
            "linucb_invert_fail_last,linucb_rad_cap_hits_last,"
            "linucb_score_cap_hits_last,linucb_invert_fail_total,"
            "linucb_rad_cap_hits_total,linucb_score_cap_hits_total,"
            "time_sec,edges_rate,rarity_rate\n");
    b->log_header_written = 1;
  }

  u64 queued_paths = afl->queued_items;
  double favored_ratio = queued_paths ? ((double)afl->queued_favored / (double)queued_paths) : 0.0;
  
  u64 ts_ms = bandit_now_ms();

  fprintf(b->log_fp,
          "%llu,%u,%s,%u,%u,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f," 
          "%0.0f,%0.4f,%0.6f,%0.6f,"
          "%llu,%0.4f,"
          "%0.6f,%0.6f,%u,"
          "%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,%0.6f,"
          "%0.6f,%0.6f,"
          "%0.4f,%u,%0.4f,%0.4f,%llu,%0.4f,%0.4f,%0.4f,%llu,%llu,"
          "%llu,%llu,%u,%u,%0.4f,%0.4f,%0.4f,%0.4f,%0.4f,%u,%llu,"
          "%llu,%llu,%llu,%llu,%llu,%llu,"
          "%0.4f,%0.6f,%0.6f\n",
          (unsigned long long)ts_ms, b->last_arm_used,
          bandit_arm_label(b->last_arm_used), b->last_arm_eff_used,
          b->last_mix_choice,
          b->last_reward, b->last_edges_term, b->last_rarity_term, 
          b->last_thrpt, b->last_thrpt_ref, b->last_thrpt_pen,
          b->last_delta_bits, b->last_delta_rarity, b->last_timeout_hz, b->last_slow_hz,
          (unsigned long long)queued_paths, favored_ratio, b->last_p90_score,
          b->last_gate_factor, b->last_dict_prob, b->last_x[0], b->last_x[1],
          b->last_x[2], b->last_x[3], b->last_x[4], b->last_x[5],
          b->last_ucb_score, b->last_base_raw,
          b->alpha, (unsigned int)b->use_contextual, b->gate_multiplier,
          b->gate_cap, (unsigned long long)b->revisit_time_ms,
          b->rarity_decay, b->rarity_ema, b->mix_p, b->last_dict_attempts,
          b->last_dict_taken, (unsigned long long)afl->adarare_dict_attempts_total,
          (unsigned long long)afl->adarare_dict_taken_total, b->dict_enable,
          b->dict_baseline_prob, b->reward_alpha, b->reward_beta,
          b->reward_gamma, b->reward_c1, b->reward_c2, b->last_p90_valid,
          (unsigned long long)b->last_p90_n, (unsigned long long)b->linucb_invert_fail_last,
          (unsigned long long)b->linucb_rad_cap_hits_last,
          (unsigned long long)b->linucb_score_cap_hits_last,
          (unsigned long long)b->linucb_invert_fail_total,
          (unsigned long long)b->linucb_rad_cap_hits_total,
          (unsigned long long)b->linucb_score_cap_hits_total,
          b->last_time_sec, b->last_edges_rate, b->last_rarity_rate);

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
          "  \"revisit_ms\": %llu,\n"
          "  \"rarity_decay\": %.4f,\n"
          "  \"rarity_ema\": %.4f,\n"
          "  \"mix_p\": %.4f,\n"
          "  \"dict_enable\": %u,\n"
          "  \"dict_baseline_prob\": %u,\n"
          "  \"reward_alpha\": %.4f,\n"
          "  \"reward_beta\": %.4f,\n"
          "  \"reward_gamma\": %.4f,\n"
          "  \"reward_c1\": %.4f,\n"
          "  \"reward_c2\": %.4f,\n"
          "  \"score_sample_n\": %u,\n"
          "  \"p90_min_samples\": %u,\n"
          "  \"log_path\": ",
          b->enabled, (unsigned long long)b->window_ms, b->num_arms,
          b->use_contextual, (unsigned int)getpid(), b->alpha, b->ridge_lambda, b->gate_multiplier,
          b->gate_cap, (unsigned long long)b->revisit_time_ms,
          b->rarity_decay, b->rarity_ema, b->mix_p, b->dict_enable,
          b->dict_baseline_prob, b->reward_alpha, b->reward_beta,
          b->reward_gamma, b->reward_c1, b->reward_c2, BANDIT_SCORE_SAMPLE_N,
          BANDIT_P90_MIN_SAMPLES);

  json_print_escaped(fp, log_path);
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
