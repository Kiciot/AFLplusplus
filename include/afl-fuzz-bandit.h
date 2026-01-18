#ifndef AFL_FUZZ_BANDIT_H
#define AFL_FUZZ_BANDIT_H

#include "types.h"

#define AFL_BANDIT_DEFAULT_ARMS 4U
#define AFL_BANDIT_DEFAULT_WINDOW_MS 5000ULL
#define AFL_BANDIT_MAX_MULTIPLIER 2.5
#define AFL_BANDIT_DICT_PROB_DEFAULT 20U

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

typedef struct bandit_arm_state {

  double total_reward;
  double pulls;

} bandit_arm_state_t;

typedef struct bandit_state {

  u8 enabled;
  u32 num_arms;
  u32 current_arm;
  double total_rounds;
  u64 window_ms;
  u64 win_start_time;
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
  u64    last_win_execs;
  u64    last_win_new_cov;
  u64    last_win_new_bits;
  double last_win_novelty;
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
  bandit_arm_state_t *arms;

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
u8 bandit_maybe_rotate(bandit_state_t *bandit, u64 now_ms);
double bandit_current_multiplier(const bandit_state_t *bandit);
u32 bandit_scale_score(bandit_state_t *bandit, u32 base_score, u32 cap);
const char *bandit_reward_label(const bandit_state_t *bandit);
const char *bandit_reward_formula_label(const bandit_state_t *bandit);
const char *bandit_gate_label(bandit_gate_t gate);
const char *bandit_rarity_norm_label(bandit_rarity_norm_t norm);
u32 bandit_dict_prob_for_arm(u32 arm_idx);

#endif
