// afl-fuzz-bandit.h
#pragma once
#include <stdint.h>

typedef struct {
  double sum_reward;
  uint64_t n;
} bandit_arm_t;

typedef struct {
  bandit_arm_t *arms;
  uint32_t num_arms;
  uint64_t total_pulls;
  uint32_t current_arm;

  // window stats
  uint64_t win_new_cov_events;   // 最小版本：新覆盖事件数（先这样）
  uint64_t win_execs;
  uint64_t win_start_ms;
  uint64_t window_ms;

} bandit_state_t;

void bandit_init(bandit_state_t *b, uint32_t k, uint64_t window_ms);
void bandit_on_new_coverage(bandit_state_t *b, uint32_t delta); // delta 可先传 1
void bandit_on_exec(bandit_state_t *b, uint64_t exec_inc);
int  bandit_maybe_rotate(bandit_state_t *b, uint64_t now_ms);   // 到期则更新并选臂
double bandit_ucb1_select(bandit_state_t *b);                   // 内部用