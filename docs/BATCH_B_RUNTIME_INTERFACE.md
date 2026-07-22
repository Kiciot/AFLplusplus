# Focused Batch B runtime interface

This is the AFL++-local interface for the six focused Batch B variants. It is
implemented on base commit `8224da1dce693d0a7de8d21cd9108c4e0e3a5b54` and
does not define FuzzBench or server-side behavior.

## Existing controls retained

The implementation keeps the existing Batch A names and semantics:

| Variable | Meaning | Default |
| --- | --- | --- |
| `AFL_BANDIT` | Legacy controller activation | unset: off |
| `AFL_BANDIT_WINDOW_MS` | Controller window length | `5000` ms |
| `AFL_ADARARE_POLICY` | `linucb`, `random_profile`, `round_robin_profile`, or `static_profile` | `linucb` |
| `AFL_ADARARE_ENABLE_A6` | Include A6 in arm selection | `1` for legacy Full |
| `AFL_ADARARE_CONTEXT_MODE` | `dynamic` or `constant` context | `dynamic` |
| `AFL_ADARARE_STATIC_ARM` | A1--A5 for `static_profile` | unset |

`AFL_ADARARE_WINDOW_MS` is not introduced. CmpLog remains controlled by the
actual `afl-fuzz -c <cmplog_binary>` argument.

## Focused controls

| Variable | Accepted values | Unset default |
| --- | --- | --- |
| `AFL_ADARARE_MODE` | `off`, `shadow`, `active` | legacy behavior: active when `AFL_BANDIT` enables the controller |
| `AFL_ADARARE_RARITY_CONTEXT` | `0` or `1` | `1` for explicit active/shadow; historical legacy path otherwise |
| `AFL_ADARARE_RARITY_REWARD` | `0` or `1` | `1` for explicit active/shadow; historical legacy path otherwise |
| `AFL_ADARARE_RARITY_GATE` | `0` or `1` | `1` for explicit active/shadow; historical legacy path otherwise |
| `AFL_ADARARE_TELEMETRY` | `0` or `1` | `1` for controller; `0` in explicit off |
| `AFL_ADARARE_AUDIT` | `0` or `1` | `0` |

All booleans are strict: values other than `0` or `1` fail before fuzzing
starts and identify the offending variable.

For legacy runs with no `AFL_ADARARE_MODE`, the historical rarity default is
retained: the three flags become enabled when the existing
`AFL_BANDIT_REWARD=rarity_mass` path is selected and remain disabled for the
historical novelty default. Explicit Batch B rows always set the three flags
and therefore do not depend on this inference.

## Mode semantics

* `off` does not call `bandit_init()`. No context, reward, LinUCB update,
  candidate selection, profile application, or periodic AdaRare telemetry is
  performed. `AFL_ADARARE_AUDIT=1` may still emit the fixed-size evidence
  sidecar.
* `shadow` initializes the same dynamic six-dimensional controller, computes
  the same reward and LinUCB candidate, updates the same model, and emits the
  same window telemetry. `bandit_apply_arm_policy()` is active-only, so all
  candidate profile actions remain unapplied and the mutation path retains its
  AFL++ default knobs. Evidence records `candidate_action_count > 0` and
  `applied_action_count = 0`.
* `active` preserves the existing controller path: candidate selection is
  applied to dictionary, havoc, favored, and new-seed profile controls.

Explicit `active` and `shadow` require `AFL_BANDIT` to be unset or non-zero;
explicit `off` requires `AFL_BANDIT` to be unset or `0`. Shadow requires
`AFL_ADARARE_POLICY=linucb`, `AFL_ADARARE_CONTEXT_MODE=dynamic`, A6 disabled,
and telemetry enabled. Off requires A6, all rarity flags, and telemetry to be
zero. Conflicts fail fast with a specific error.

## Rarity ablation

`batchb_adarare_no_rarity` sets all three rarity flags to zero. The model
dimension remains six and the rarity coordinate is exactly zero. Rarity mass,
rarity reward, rarity-dependent progress, rarity tie-breaking, queue rarity
pressure, and rarity energy shaping are disabled; coverage maps, CmpLog,
throughput, the general non-rarity progress gate, the dynamic controller, and
A6's independent control remain available. The complete source mapping is in
[`BATCH_B_RARITY_SOURCE_MAP.md`](BATCH_B_RARITY_SOURCE_MAP.md).

## Runtime evidence

With `AFL_ADARARE_AUDIT=1`, the main node atomically rewrites
`.adarare_runtime_evidence.json` at startup, controller boundaries, and clean
shutdown. It contains schema version, AFL++ version, embedded checkout
commit, exact argv, mode/flags, controller window count, candidate/applied
counts and per-arm arrays, CmpLog activation/path/count, profile knobs, and a
clean-shutdown flag. It never contains fuzz inputs, corpus contents, secrets,
or tokens. CmpLog count increments only after the actual CmpLog target child
execution call and remains zero without `-c`.

The six exact rows are maintained in
[`BATCH_B_FOCUSED_VARIANT_MANIFEST.md`](BATCH_B_FOCUSED_VARIANT_MANIFEST.md)
and its TSV companion.
