# Focused Batch B runtime variant manifest

The six rows below are the complete focused Batch B matrix. They use the
existing `AFL_BANDIT_WINDOW_MS` control and the existing Batch A policy names.
CmpLog is activated only by `afl-fuzz -c <cmplog_binary>`; no AdaRare variable
pretends to enable it.

| Variant | Mode | A6 | Rarity context/reward/gate | Telemetry | Audit | CmpLog |
| --- | --- | ---: | --- | ---: | ---: | --- |
| `batchb_aflpp_default` | `off` | 0 | 0/0/0 | 0 | 1 | no `-c` |
| `batchb_aflpp_cmplog_matched` | `off` | 0 | 0/0/0 | 0 | 1 | same `-c` as AdaRare |
| `batchb_aflpp_shadow` | `shadow` | 0 | 1/1/1 | 1 | 1 | same `-c` |
| `batchb_adarare_full` | `active` | 1 | 1/1/1 | 1 | 1 | same `-c` |
| `batchb_adarare_no_a6` | `active` | 0 | 1/1/1 | 1 | 1 | same `-c` |
| `batchb_adarare_no_rarity` | `active` | 0 | 0/0/0 | 1 | 1 | same `-c` |

## Exact environment values

The following uses `AFL_BANDIT=0` for the two AFL++ controls and `AFL_BANDIT=1`
for the four controller variants. `AFL_BANDIT_WINDOW_MS=5000` is explicit so
the server manifest does not depend on an inherited value.

### `batchb_aflpp_default`

```text
AFL_BANDIT=0
AFL_ADARARE_MODE=off
AFL_ADARARE_ENABLE_A6=0
AFL_ADARARE_RARITY_CONTEXT=0
AFL_ADARARE_RARITY_REWARD=0
AFL_ADARARE_RARITY_GATE=0
AFL_ADARARE_TELEMETRY=0
AFL_ADARARE_AUDIT=1
```

Run without `-c`.

### `batchb_aflpp_cmplog_matched`

Use the same values as `batchb_aflpp_default`, plus the same
`-c <cmplog_binary>` used by the AdaRare rows.

### `batchb_aflpp_shadow`

```text
AFL_BANDIT=1
AFL_BANDIT_WINDOW_MS=5000
AFL_ADARARE_MODE=shadow
AFL_ADARARE_POLICY=linucb
AFL_ADARARE_ENABLE_A6=0
AFL_ADARARE_RARITY_CONTEXT=1
AFL_ADARARE_RARITY_REWARD=1
AFL_ADARARE_RARITY_GATE=1
AFL_ADARARE_TELEMETRY=1
AFL_ADARARE_AUDIT=1
```

The controller computes the candidate and updates the model, but the
candidate cannot change profile knobs. Every telemetry row records
`action_applied=false` for that candidate.

### `batchb_adarare_full`

Use `AFL_ADARARE_MODE=active`, `AFL_ADARARE_ENABLE_A6=1`, and the three
rarity flags set to `1`; keep `AFL_BANDIT=1`, `AFL_BANDIT_WINDOW_MS=5000`,
`AFL_ADARARE_POLICY=linucb`, telemetry `1`, and audit `1`.

### `batchb_adarare_no_a6`

Use the Full row with `AFL_ADARARE_ENABLE_A6=0`. A6 is excluded from both
selection and application; all other Full rarity and CmpLog settings remain.

### `batchb_adarare_no_rarity`

Use the Full row with `AFL_ADARARE_ENABLE_A6=0` and all three rarity flags set
to `0`. Coverage, CmpLog, throughput, dynamic controller, and the six-element
model remain enabled.

All controller rows use the same `-c <cmplog_binary>` argument as the matched
AFL++ CmpLog row. No separate no-rarity-context or no-rarity-reward variant is
part of this focused matrix.
