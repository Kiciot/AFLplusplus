/*
   AFL++ - bandit-based scheduling helpers
   ---------------------------------------

   Minimal UCB1 contextual bandit wrapper for online arm selection that
   adjusts seed energy without touching the core fuzzing loop.
*/

#include "afl-fuzz.h"
#include <float.h>
#include <math.h>
#include <string.h>

static const double bandit_arm_multipliers[] = {1.0, 1.3, 1.6, 2.0};

static inline u32 bandit_default_arm_count(void) {

  return sizeof(bandit_arm_multipliers) / sizeof(bandit_arm_multipliers[0]);

}

static inline double bandit_multiplier_for_arm(u32 arm_idx) {

  u32 max_idx = bandit_default_arm_count();
  if (arm_idx >= max_idx) { return 1.0; }

  double mult = bandit_arm_multipliers[arm_idx];
  return mult > AFL_BANDIT_MAX_MULTIPLIER ? AFL_BANDIT_MAX_MULTIPLIER : mult;

}

static const u32 bandit_dict_probs[] = {0, 10, 30, 60};

u32 bandit_dict_prob_for_arm(u32 arm_idx) {

  u32 max_idx = (u32)(sizeof(bandit_dict_probs) / sizeof(bandit_dict_probs[0]));
  if (arm_idx >= max_idx) { return bandit_dict_probs[max_idx - 1]; }
  return bandit_dict_probs[arm_idx];

}

const char *bandit_rarity_norm_label(bandit_rarity_norm_t norm) {

  switch (norm) {

    case BANDIT_RARITY_NORM_PATH_LEN:
      return "path_len";
    case BANDIT_RARITY_NORM_NONE:
    default:
      return "none";

  }

}

void bandit_init(bandit_state_t *bandit, u32 arms, u64 window_ms) {

  if (!bandit) { return; }

  bandit_deinit(bandit);
  bandit->reward_mode = BANDIT_REWARD_NOVELTY;
  bandit->reward_formula = BANDIT_REWARD_RATE_COST;
  bandit->beta = 0.01;
  bandit->gamma = 0.01;

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
  bandit->window_ms = window_ms;
  bandit->win_start_time = get_cur_time();
  bandit->hit_max = 0;
  bandit->last_win_gate = 1.0;
  bandit->last_win_rarity_mass = 0.0;
  bandit->last_win_gate_execavg = 1.0;
  bandit->rarity_norm = BANDIT_RARITY_NORM_PATH_LEN;
  bandit->discount = 1.0;
  bandit->warmup_windows = 10;
  bandit->in_warmup = 0;

}

void bandit_deinit(bandit_state_t *bandit) {

  if (!bandit) { return; }
  ck_free(bandit->arms);
  memset(bandit, 0, sizeof(bandit_state_t));

}

void bandit_on_new_cov(bandit_state_t *bandit, u64 new_bits,
                       double novelty_delta, double gate) {

  if (!bandit || !bandit->enabled) { return; }
  if (!bandit->win_start_time) { bandit->win_start_time = get_cur_time(); }
  bandit->win_new_cov += 1;
  bandit->win_new_bits += new_bits;
  bandit->win_novelty += novelty_delta;
  u64 samples = new_bits ? new_bits : 1;
  bandit->win_gate_sum += gate * (double)samples;
  bandit->win_gate_samples += samples;

}

void bandit_on_rarity_mass(bandit_state_t *bandit, double rarity_mass,
                           u64 path_len) {

  if (!bandit || !bandit->enabled) { return; }
  if (!bandit->win_start_time) { bandit->win_start_time = get_cur_time(); }
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

  if (!bandit || !bandit->enabled) { return; }
  bandit->win_gate_exec_sum += gate;
  bandit->win_gate_exec_samples += 1;

}

void bandit_on_exec(bandit_state_t *bandit, u64 execs, u64 time_us,
                    u64 timeouts, u64 slow_execs) {

  if (!bandit || !bandit->enabled) { return; }
  if (!bandit->win_start_time) { bandit->win_start_time = get_cur_time(); }
  bandit->win_execs += execs;
  bandit->win_time_us += time_us;
  bandit->win_timeouts += timeouts;
  bandit->win_slow_execs += slow_execs;

}

u8 bandit_maybe_rotate(bandit_state_t *bandit, u64 now_ms) {

  if (!bandit || !bandit->enabled || !bandit->arms || !bandit->window_ms) {

    return 0;

  }

  if (!bandit->win_start_time) { bandit->win_start_time = now_ms; }
  if (now_ms - bandit->win_start_time < bandit->window_ms) { return 0; }

  u64 rotate_start_us = get_cur_time_us();
  bandit_arm_state_t *current = &bandit->arms[bandit->current_arm];
  bandit->in_warmup = bandit->rotate_count < bandit->warmup_windows;

  /* Apply discounting to adapt to non-stationarity. */
  if (bandit->discount > 0.0 && bandit->discount < 1.0) {

    for (u32 i = 0; i < bandit->num_arms; ++i) {

      bandit->arms[i].pulls *= bandit->discount;
      bandit->arms[i].total_reward *= bandit->discount;

    }

    bandit->total_rounds *= bandit->discount;

  }

  double reward = (double)bandit->win_new_cov;
  double execs = (double)(bandit->win_execs ? bandit->win_execs : 1);
  double base_rate = reward / execs;

  switch (bandit->reward_mode) {

    case BANDIT_REWARD_BITS:
      base_rate = (double)bandit->win_new_bits / execs;
      break;

    case BANDIT_REWARD_NOVELTY:
      base_rate = bandit->win_novelty / execs;
      break;

    case BANDIT_REWARD_RARITY_MASS:
      base_rate = bandit->win_rarity_mass / execs;
      break;

    case BANDIT_REWARD_EVENT:
    default:
      break;

  }

  if (bandit->reward_formula == BANDIT_REWARD_RATE_COST) {

    double timeout_rate = (double)bandit->win_timeouts / execs;
    double slow_rate = (double)bandit->win_slow_execs / execs;
    reward = base_rate - bandit->beta * timeout_rate -
             bandit->gamma * slow_rate;

  } else {

    reward = base_rate;

  }

  current->pulls++;
  current->total_reward += reward;
  bandit->total_rounds += 1.0;

  bandit->last_reward = reward;
  bandit->last_win_execs = bandit->win_execs;
  bandit->last_win_new_cov = bandit->win_new_cov;
  bandit->last_win_new_bits = bandit->win_new_bits;
  bandit->last_win_novelty = bandit->win_novelty;
  bandit->last_win_rarity_mass = bandit->win_rarity_mass;
  bandit->last_win_rarity_samples = bandit->win_rarity_samples;
  bandit->last_path_len_sum = bandit->win_path_len_sum;
  bandit->last_path_len_avg =
      bandit->win_rarity_samples
          ? (double)bandit->win_path_len_sum /
                (double)bandit->win_rarity_samples
          : 0.0;
  if (bandit->rarity_norm == BANDIT_RARITY_NORM_PATH_LEN) {

    bandit->last_rarity_density =
        bandit->win_rarity_samples
            ? bandit->win_rarity_mass / (double)bandit->win_rarity_samples
            : 0.0;

  } else {

    bandit->last_rarity_density =
        bandit->win_path_len_sum
            ? bandit->win_rarity_mass / (double)bandit->win_path_len_sum
            : 0.0;

  }
  bandit->last_win_time_us = bandit->win_time_us;
  bandit->last_win_timeouts = bandit->win_timeouts;
  bandit->last_win_slow_execs = bandit->win_slow_execs;
  bandit->last_win_gate_samples = bandit->win_gate_samples;
  bandit->last_win_gate =
      bandit->win_gate_samples ? bandit->win_gate_sum / bandit->win_gate_samples
                               : 1.0;
  bandit->last_win_gate_exec_samples = bandit->win_gate_exec_samples;
  bandit->last_win_gate_execavg =
      bandit->win_gate_exec_samples
          ? bandit->win_gate_exec_sum / bandit->win_gate_exec_samples
          : 1.0;

  u32    next_arm = bandit->current_arm;
  double best_score = -DBL_MAX;

  for (u32 i = 0; i < bandit->num_arms; ++i) {

    double score;
    if (bandit->arms[i].pulls <= 0.0) {

      /* force initial exploration */
      score = DBL_MAX;

    } else {

      double pulls = bandit->arms[i].pulls;
      double mean = bandit->arms[i].total_reward / pulls;
      double bonus =
          sqrt((2.0 * log((double)(bandit->total_rounds + 1.0))) / pulls);
      score = mean + bonus;

    }

    if (score > best_score) {

      best_score = score;
      next_arm = i;

      if (score == DBL_MAX) { break; }

    }

  }

  bandit->current_arm = bandit->in_warmup ? bandit->current_arm : next_arm;
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
  bandit->win_start_time = now_ms;

  u64 rotate_us = get_cur_time_us() - rotate_start_us;
  bandit->last_rotate_us = rotate_us;
  bandit->rotate_us_total += rotate_us;
  bandit->rotate_count++;

  return 1;

}

double bandit_current_multiplier(const bandit_state_t *bandit) {

  if (!bandit || !bandit->enabled || bandit->in_warmup) { return 1.0; }
  return bandit_multiplier_for_arm(bandit->current_arm);

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

    case BANDIT_REWARD_BITS:
      return "bits";
    case BANDIT_REWARD_NOVELTY:
      return "novelty";
    case BANDIT_REWARD_RARITY_MASS:
      return "rarity_mass";
    case BANDIT_REWARD_EVENT:
    default:
      return "event";
}
}

const char *bandit_reward_formula_label(const bandit_state_t *bandit) {

  if (!bandit || !bandit->enabled) { return "off"; }

  switch (bandit->reward_formula) {

    case BANDIT_REWARD_RATE:
      return "rate";
    case BANDIT_REWARD_RATE_COST:
    default:
      return "rate_cost";

  }
}

const char *bandit_gate_label(bandit_gate_t gate) {

  switch (gate) {

    case BANDIT_GATE_EXEC_US:
      return "exec_us";
    case BANDIT_GATE_PATH_LEN:
      return "path_len";
    case BANDIT_GATE_NONE:
    default:
      return "none";

  }

}
