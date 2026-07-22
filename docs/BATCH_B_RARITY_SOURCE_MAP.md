# Batch B rarity source map

This map covers every rarity-dependent path in the Batch A controller found
in the AFL++ checkout. The three flags are independent controls:

* `AFL_ADARARE_RARITY_CONTEXT=0` removes rarity from the context coordinate.
* `AFL_ADARARE_RARITY_REWARD=0` removes rarity reward/profile contributions.
* `AFL_ADARARE_RARITY_GATE=0` removes rarity from the progress alternative.

The focused `batchb_adarare_no_rarity` row sets all three to zero. The model
still has six coordinates and the same six-by-six `A` matrices; only the
rarity coordinate and rarity-derived values are zeroed.

| Rarity path | Source location | Control and no-rarity result |
| --- | --- | --- |
| Rare-edge/frequency mass scan | `src/afl-fuzz-bitmap.c:has_new_bits()` | The scan runs only when at least one rarity flag is enabled. `edge_hit` and `edge_last_seen` continue to serve normal coverage bookkeeping. |
| Path-length input for rarity normalization | `src/afl-fuzz-bitmap.c:has_new_bits()` | Path length is collected for rarity logic only; the general `BANDIT_GATE_PATH_LEN` gate remains available. |
| Rarity mass accumulation | `src/afl-fuzz-bitmap.c` -> `bandit_on_rarity_mass()` | The hook is called only when rarity context, reward, or gate is enabled. With all flags zero, `win_rarity_mass` stays exactly zero. |
| Rarity-mass queue score | `src/afl-fuzz-bitmap.c` | The `queue_entry.rarity_score` EMA is updated only for rarity reward mode with `RARITY_REWARD=1`. |
| Rarity reward base | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | `BANDIT_REWARD_RARITY_MASS` contributes zero when `RARITY_REWARD=0`. |
| Rarity rate and P90 | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | Rarity rate/reservoir input is zero and not sampled when all rarity flags are zero. |
| Rarity tanh reward term | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | `rarity_term=0` when `RARITY_REWARD=0`; `rw_beta` is removed before reward-weight normalization, so non-rarity reward weights are preserved. |
| Rarity-modulated CmpLog reward | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | `cmp_rarity_lambda` is effective only with `RARITY_REWARD=1`; the ordinary CmpLog term remains available. |
| Rarity progress alternative | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | `win_rarity_mass > BANDIT_PROGRESS_RARITY_EPS` participates only with `RARITY_GATE=1`. Coverage and CmpLog progress alternatives remain. |
| Rarity context coordinate | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | `raw_x[1]` and its EMA are exactly zero with `RARITY_CONTEXT=0`; dimensions and all other coordinates remain. |
| Rarity arm EMA | `src/afl-fuzz-bandit.c:bandit_maybe_rotate()` | Rarity observations are zero when the rarity path is disabled. The direct rarity tie-break metric is forced to zero when all flags are zero. |
| Rarity p90 queue pressure | `src/afl-fuzz-queue.c` | Active-only decay, p90 sampling, and queue pressure; off, shadow, and all-zero rarity bypass it. |
| Rarity energy/profile boost | `src/afl-fuzz-bandit.c:bandit_energy_boost()` | Returns `1.0` for off, shadow, and no-rarity; active non-rarity profile controls remain separate. |

## Non-rarity invariants

No-rarity does not clear or bypass AFL++ coverage maps, `edge_hit`, virgin
maps, CmpLog execution, throughput accounting, the dynamic controller, or
the six-dimensional LinUCB matrices. CmpLog remains controlled only by
`afl-fuzz -c`; its execution counter is independent of the rarity flags.
