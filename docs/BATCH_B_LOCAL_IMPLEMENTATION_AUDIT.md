# Focused Batch B local implementation audit

## Scope and checkout

* Repository used for implementation:
  `/Users/kiciot/Project/AFLplusplus-batchb-focused`
* Base checkout:
  `8224da1dce693d0a7de8d21cd9108c4e0e3a5b54`
* Working branch: `adarare-batch-b-focused-v1`
* Protected old checkout:
  `/Users/kiciot/Project/AFLplusplus` was inspected read-only; its dirty
  deletions and untracked files were not stashed, reset, restored, or removed.
* No FuzzBench tree, server, paper, artifact, or formal fuzzing run was used.

## Implementation audit

The runtime mode is parsed before controller activation. `off` returns before
allocation of the bandit model. `shadow` runs the same rotation, reward,
context, LinUCB score, and model update code as `active`, while the single arm
application function has an explicit active-mode guard. The three rarity flags
are applied at bitmap collection, reward, progress, context, arm tie-break,
queue-pressure, and energy-shaping sites; the source-level map is in
[`BATCH_B_RARITY_SOURCE_MAP.md`](BATCH_B_RARITY_SOURCE_MAP.md).

The evidence writer is main-node-only, uses a temporary file plus rename, and
does not write on each target execution. The CmpLog counter is incremented in
memory immediately after `fuzz_run_target()` on the resolved `-c` service
path, including timeout/stop handling; it is emitted only through existing
telemetry/evidence writes.

## Verification performed

| Check | Result |
| --- | --- |
| `gmake -B TEST_MMAP=1 afl-fuzz` | pass on Darwin arm64; only duplicate-library linker warnings |
| `./test/test-adarare-batch-b.sh` | pass: 33 deterministic checks |
| `gmake unit` | expected Darwin skip: unit tests require GNU linker `--wrap` |
| `./test/test-adarare-batch-a.sh` | blocked before fuzzing: local `afl-cc` reports `no compiler mode available` |
| Local off/shadow/active/no-A6/no-rarity/evidence smoke | pass inside the 33-check test; each run is seconds |
| Long fuzzing, FuzzBench, benchmark, server connection | not run |

The Batch A failure is a local toolchain limitation in the existing wrapper
build (the LLVM/clang installation is mismatched and no usable compiler mode
is available), not a passed or failed Batch B runtime assertion. The focused
test uses a short manually instrumented target only to exercise the AFL++
runtime interface under this Mac toolchain.

## Handoff boundary

Only the AFL++ runtime source, tests, and local documentation belong in this
branch. The server-side checkout must use the final commit reported at
handoff, not the protected old checkout or an artifact copy.
