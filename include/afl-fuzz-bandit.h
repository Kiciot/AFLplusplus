#ifndef AFL_FUZZ_BANDIT_H
#define AFL_FUZZ_BANDIT_H

#include "types.h"

#define AFL_BANDIT_DEFAULT_ARMS 4U
#define AFL_BANDIT_MAX_ARMS 6U
#define AFL_BANDIT_DEFAULT_WINDOW_MS 5000ULL
#define AFL_BANDIT_MAX_MULTIPLIER 2.5
#define AFL_BANDIT_DICT_PROB_DEFAULT 20U
#define BANDIT_SCORE_SAMPLE_N 1024
#define BANDIT_DEFAULT_RARITY_DECAY 0.995
#define BANDIT_LINUCB_RIDGE 10.0

typedef enum {

  BANDIT_RARITY_NORM_NONE = 0,
  BANDIT_RARITY_NORM_PATH_LEN

} bandit_rarity_norm_t;

typedef enum {

  BANDIT_REWARD_EVENT = 0,
  BANDIT_REWARD_BITS,
  BANDIT_REWARD_NOVELTY,
  BANDIT_REWARD_RARITY_MASS

} bandit_reward_t;

typedef enum {

  BANDIT_REWARD_RATE = 0,
  BANDIT_REWARD_RATE_COST

} bandit_reward_formula_t;

typedef enum {

  BANDIT_GATE_NONE = 0,
  BANDIT_GATE_EXEC_US,
  BANDIT_GATE_PATH_LEN

} bandit_gate_t;

typedef enum {
  BANDIT_ARM_A1 = 0,
  BANDIT_ARM_A2 = 1,
  BANDIT_ARM_A3 = 2,
  BANDIT_ARM_A4 = 3,
  BANDIT_ARM_A5 = 4,
  BANDIT_ARM_A6 = 5
} bandit_arm_id_t;

typedef struct bandit_arm_state {

  double pulls;        /* Discounted execution weight for UCB. */
  double total_reward; /* Discounted total reward. */
  u64    selections;   /* Non-discounted selection count. */
  u64    last_selected_round; /* Last global selection round. */
  u64    last_selected_ms;    /* Last selection time (ms). */
  double A[6][6];      /* LinUCB design matrix per arm. */
  double b[6];         /* LinUCB target vector per arm. */

} bandit_arm_state_t;

typedef struct bandit_state {

  u8 enabled;
  struct afl_state *owner;
  u64 rng_state; /* Decoupled RNG for bandit decisions */
  u32 num_arms;
  u32 current_arm;
  u32 current_arm_eff; /* Frozen effective arm for current window (A6 -> A1/A2). */
  bandit_arm_state_t *arms;
  void  *score_res;        /* Reservoir for reward samples */
  void  *edges_rate_res;   /* Reservoir for edges/sec */
  void  *rarity_rate_res;  /* Reservoir for rarity/sec */
  u8     verify_enabled;   /* Enable verification logging */
  u8     rng_seeded_from_owner; /* Whether RNG seeded from owner */
  u32    rng_log_idx;      /* Logged RNG outputs count */
  u32    rng_log[32];      /* First RNG outputs for reproducibility checks */
  char  *verify_log_path;  /* Optional verification log path */
  FILE  *verify_fp;        /* Verification log handle */
  u64 total_selections;
  double total_rounds;
  u64 window_ms;
  u64 win_start_time;
  u64 win_arm_ms[AFL_BANDIT_MAX_ARMS];
  u64 win_last_ts;
  u32 win_last_arm;
  u64 win_new_cov;
  u64 win_new_bits;
  u64 win_execs;
  double win_novelty;
  double win_rarity_mass;
  u64    win_rarity_samples;
  u64    win_path_len_sum;
  double win_gate_exec_sum;
  u64    win_gate_exec_samples;
  double last_reward;
  double last_raw_reward;
  double last_gate_factor;
  u64    last_win_execs;
  u64    last_win_new_cov;
  u64    last_win_new_bits;
  double last_win_novelty;
  double last_base_raw;
  double last_win_rarity_mass;
  u64    last_win_rarity_samples;
  u64    last_path_len_sum;
  double last_path_len_avg;
  double last_rarity_density;
  bandit_reward_t reward_mode;
  bandit_reward_formula_t reward_formula;
  bandit_rarity_norm_t rarity_norm;
  double beta;
  double gamma;
  double discount;
  u64    warmup_windows;
  u8     in_warmup;
  u8     mix_choice; /* Used when current_arm == BANDIT_ARM_A6 */
  u8     last_mix_choice;
  u32    last_arm_used;
  u32    last_arm_eff_used;
  double gate_multiplier;
  double gate_cap;
  u64    revisit_time_ms;
  u64    last_improve_ms;
  u64    last_revisit_ms;
  u32    stagnation_windows;
  double rarity_decay;
  double rarity_ema;
  double mix_p;
  u64    win_time_us;
  u64    win_timeouts;
  u64    win_slow_execs;
  u64    last_win_time_us;
  u64    last_win_timeouts;
  u64    last_win_slow_execs;
  double win_gate_sum;
  u64    win_gate_samples;
  double last_win_gate;
  u64    last_win_gate_samples;
  double last_win_gate_execavg;
  u64    last_win_gate_exec_samples;
  u64    rotate_us_total;
  u64    rotate_count;
  u64    last_rotate_us;
  u64    novelty_us_total;
  u64    novelty_samples;
  u64    last_novelty_us;
  u32 hit_max;
  double thrpt_ref_ema;
  u8     thrpt_ref_inited;
  double last_thrpt;
  double last_thrpt_ref;
  double last_thrpt_pen;
  double last_timeout_hz;
  double last_slow_hz;
  double last_delta_bits;
  double last_delta_edges;
  double last_delta_rarity;
  double last_time_sec;
  double last_edges_rate;
  double last_rarity_rate;
  double last_edges_term;
  double last_rarity_term;
  double last_x[6];
  double last_ucb_score;
  u64    linucb_invert_fail_total;
  u64    linucb_rad_cap_hits_total;
  u64    linucb_score_cap_hits_total;
  u64    linucb_invert_fail_win;
  u64    linucb_rad_cap_hits_win;
  u64    linucb_score_cap_hits_win;
  u64    linucb_invert_fail_last;
  u64    linucb_rad_cap_hits_last;
  u64    linucb_score_cap_hits_last;
  double alpha;
  u8     use_contextual;
  double ridge_lambda;
  u32    last_dict_prob;
  u64    last_dict_attempts;
  u64    last_dict_taken;
  u32    last_p90_n;
  u8     last_p90_valid;
  double score_sample[BANDIT_SCORE_SAMPLE_N];
  u32    score_sample_cnt;
  u64    score_sample_seen;
  double last_p90_score;
  FILE  *log_fp;
  char  *log_path;
  u8     log_header_written;
  u8     config_written;
  u32    dict_baseline_prob;
  u32    dict_enable;
  double reward_alpha;
  double reward_beta;
  double reward_gamma;
  double reward_c1;
  double reward_c2;

} bandit_state_t;

void bandit_init(bandit_state_t *bandit, u32 arms, u64 window_ms);
void bandit_deinit(bandit_state_t *bandit);
void bandit_on_new_cov(bandit_state_t *bandit, u64 new_bits,
                       double novelty_delta, double gate);
void bandit_on_rarity_mass(bandit_state_t *bandit, double rarity_mass,
                           u64 path_len);
void bandit_on_exec_gate(bandit_state_t *bandit, double gate);
void bandit_on_exec(bandit_state_t *bandit, u64 execs, u64 time_us,
                    u64 timeouts, u64 slow_execs);
u8 bandit_maybe_rotate(bandit_state_t *bandit);
double bandit_current_multiplier(const bandit_state_t *bandit);
u32 bandit_scale_score(bandit_state_t *bandit, u32 base_score, u32 cap);
const char *bandit_reward_label(const bandit_state_t *bandit);
const char *bandit_reward_formula_label(const bandit_state_t *bandit);
const char *bandit_gate_label(bandit_gate_t gate);
const char *bandit_rarity_norm_label(bandit_rarity_norm_t norm);
const char *bandit_arm_label(u32 arm);
u32 bandit_dict_prob_for_arm(u32 arm_idx);
double bandit_energy_boost(const bandit_state_t *bandit, double z);
void bandit_score_sample_push(bandit_state_t *bandit, double score,
                             u32 rand_u32);
void bandit_score_sample_reset(bandit_state_t *bandit);
double bandit_score_sample_p90(bandit_state_t *bandit);
void bandit_set_log_dir(bandit_state_t *bandit, const char *out_dir);
struct afl_state;
void bandit_log_window(struct afl_state *afl);
void bandit_set_owner(bandit_state_t *bandit, struct afl_state *afl);
u32 bandit_current_dict_prob(const bandit_state_t *bandit);
void adarare_write_config_snapshot(struct afl_state *afl);

#endif
