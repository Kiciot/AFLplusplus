/*
   american fuzzy lop++ - cmplog execution routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <math.h>
#include "cmplog.h"

enum {

  CMPLOG_ATTR_IS_FP = 8

};

typedef struct {

  u64 best_dist;
  u32 best_match;
  u8  best_dist_valid;
  u8  best_match_valid;

} cmplog_runtime_state_t;

static cmplog_runtime_state_t cmplog_runtime_state[CMP_MAP_W * 2U];

void cmplog_reset_runtime_progress(void) {

  memset(cmplog_runtime_state, 0, sizeof(cmplog_runtime_state));

}

static inline u64 cmplog_runtime_abs_diff_u64(u64 lhs, u64 rhs) {

  return (lhs >= rhs) ? (lhs - rhs) : (rhs - lhs);

}

static inline u64 cmplog_runtime_shape_mask(u32 shape_bytes) {

  if (!shape_bytes) return 0;
  if (shape_bytes >= sizeof(u64)) return ULLONG_MAX;
  return (1ULL << (shape_bytes * 8)) - 1ULL;

}

static inline u32 cmplog_runtime_equal_bytes(const u8 *lhs, const u8 *rhs,
                                             u32 nbytes) {

  u32 matched = 0;
  for (u32 i = 0; i < nbytes; ++i) {
    if (lhs[i] == rhs[i]) matched++;
  }

  return matched;

}

static inline void cmplog_runtime_copy_ins_bytes(u8 *lhs, u8 *rhs,
                                                 const struct cmp_operands *o) {

  memcpy(lhs, &o->v0, 8);
  memcpy(lhs + 8, &o->v0_128, 8);
  memcpy(lhs + 16, &o->v0_256_0, 8);
  memcpy(lhs + 24, &o->v0_256_1, 8);
  memcpy(rhs, &o->v1, 8);
  memcpy(rhs + 8, &o->v1_128, 8);
  memcpy(rhs + 16, &o->v1_256_0, 8);
  memcpy(rhs + 24, &o->v1_256_1, 8);

}

static double cmplog_post_exec_progress(afl_state_t *afl) {

  if (!afl || !afl->bandit.enabled || !afl->bandit.cmp_reward ||
      !afl->shm.cmp_map) {
    return 0.0;
  }

  u8 producer_mode = afl->bandit.cmp_producer_mode;
  if (producer_mode > 2) producer_mode = 2;
  if (!producer_mode) return 0.0;

  double dist_delta_total = 0.0;
  double match_delta_total = 0.0;

  for (u32 key = 0; key < CMP_MAP_W; ++key) {

    struct cmp_header *h = &afl->shm.cmp_map->headers[key];
    if (!h->hits) continue;

    u32 shape_bytes = SHAPE_BYTES(h->shape);
    if (!shape_bytes) continue;

    u32 capped_bytes = shape_bytes > 32 ? 32 : shape_bytes;
    u32 slot = key + (h->type == CMP_TYPE_RTN ? CMP_MAP_W : 0U);
    cmplog_runtime_state_t *st = &cmplog_runtime_state[slot];

    if (h->type == CMP_TYPE_INS) {

      u32 loggeds = MIN((u32)h->hits, (u32)CMP_MAP_H);
      u64 cur_best_dist = 0;
      u32 cur_best_match = 0;
      u8  cur_best_dist_valid = 0;
      u8  cur_best_match_valid = 0;

      for (u32 i = 0; i < loggeds; ++i) {

        const struct cmp_operands *o = &afl->shm.cmp_map->log[key][i];

        if (producer_mode != 1 && shape_bytes <= sizeof(u64) &&
            !(h->attribute & CMPLOG_ATTR_IS_FP)) {

          u64 mask = cmplog_runtime_shape_mask(shape_bytes);
          u64 lhs = o->v0 & mask;
          u64 rhs = o->v1 & mask;
          u64 dist = cmplog_runtime_abs_diff_u64(lhs, rhs);
          if (!cur_best_dist_valid || dist < cur_best_dist) {
            cur_best_dist = dist;
            cur_best_dist_valid = 1;
          }

        }

        u8 lhs_bytes[32];
        u8 rhs_bytes[32];
        cmplog_runtime_copy_ins_bytes(lhs_bytes, rhs_bytes, o);
        u32 match = cmplog_runtime_equal_bytes(lhs_bytes, rhs_bytes, capped_bytes);
        if (!cur_best_match_valid || match > cur_best_match) {
          cur_best_match = match;
          cur_best_match_valid = 1;
        }

      }

      if (cur_best_dist_valid) {
        if (st->best_dist_valid && cur_best_dist < st->best_dist) {
          dist_delta_total += (double)(st->best_dist - cur_best_dist);
        }
        if (!st->best_dist_valid || cur_best_dist < st->best_dist) {
          st->best_dist = cur_best_dist;
          st->best_dist_valid = 1;
        }
      }

      if (cur_best_match_valid) {
        if (st->best_match_valid && cur_best_match > st->best_match) {
          match_delta_total += (double)(cur_best_match - st->best_match);
        }
        if (!st->best_match_valid || cur_best_match > st->best_match) {
          st->best_match = cur_best_match;
          st->best_match_valid = 1;
        }
      }

    } else if (h->type == CMP_TYPE_RTN) {

      u32 loggeds = MIN((u32)h->hits, (u32)CMP_MAP_RTN_H);
      u32 cur_best_match = 0;
      u8  cur_best_match_valid = 0;

      for (u32 i = 0; i < loggeds; ++i) {

        const struct cmpfn_operands *o =
            &((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[i];
        u32 match = cmplog_runtime_equal_bytes(o->v0, o->v1, capped_bytes);
        if (!cur_best_match_valid || match > cur_best_match) {
          cur_best_match = match;
          cur_best_match_valid = 1;
        }

      }

      if (cur_best_match_valid) {
        if (st->best_match_valid && cur_best_match > st->best_match) {
          match_delta_total += (double)(cur_best_match - st->best_match);
        }
        if (!st->best_match_valid || cur_best_match > st->best_match) {
          st->best_match = cur_best_match;
          st->best_match_valid = 1;
        }
      }

    }

  }

  /* This reward is computed only after the real cmplog child ran and filled
     cmp_map; it does not use Redqueen pre-mutation orig/colorization diffs. */
  double reward = log1p(dist_delta_total) + 0.5 * log1p(match_delta_total);
  double min_gain = afl->bandit.cmp_min_gain;
  if (!isfinite(min_gain) || min_gain < 0.0) min_gain = 0.25;
  if (!isfinite(reward) || reward < 0.0) reward = 0.0;
  if (reward + 1e-12 < min_gain) reward = 0.0;
  if (reward > 8.0) reward = 8.0;
  return reward;

}

void cmplog_exec_child(afl_forkserver_t *fsrv, char **argv) {

  setenv("___AFL_EINS_ZWEI_POLIZEI___", "1", 1);

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }

  if (!fsrv->unicorn_mode && !fsrv->qemu_mode && !fsrv->frida_mode &&
      argv[0] != fsrv->cmplog_binary) {

    fsrv->target_path = argv[0] = fsrv->cmplog_binary;

  }

  execv(fsrv->target_path, argv);

}

u8 common_fuzz_cmplog_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8  fault;
  u32 tmp_len = write_to_testcase(afl, (void **)&out_buf, len, 0);

  if (likely(tmp_len)) {

    len = tmp_len;

  } else {

    len = write_to_testcase(afl, (void **)&out_buf, len, 1);

  }

  fault = fuzz_run_target(afl, &afl->cmplog_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_OK) {

    double progress = cmplog_post_exec_progress(afl);
    if (progress > 0.0) { bandit_on_cmplog_progress(&afl->bandit, progress); }

  }

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_items;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    return 1;

  }

  if (afl->bandit.enabled) { afl->bandit_win_cmplog_execs++; }

  return 0;

}
