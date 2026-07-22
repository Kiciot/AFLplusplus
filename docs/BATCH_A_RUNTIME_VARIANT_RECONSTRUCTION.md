# Batch A runtime variant reconstruction

Base commit: `8224da1dce693d0a7de8d21cd9108c4e0e3a5b54`

This reconstruction is from the Batch A source and its existing
`test/test-adarare-batch-a.sh`. It records the runtime configurations that
must remain compatible while focused Batch B controls are added.

All rows use the same AFL++ binary and retain the existing `AFL_BANDIT=1`
activation. An omitted value means the source default, not a new behavior.

| Batch A profile | `AFL_ADARARE_POLICY` | `AFL_ADARARE_ENABLE_A6` | `AFL_ADARARE_CONTEXT_MODE` | `AFL_ADARARE_STATIC_ARM` |
| --- | --- | --- | --- | --- |
| Full AdaRare / default LinUCB | `linucb` or unset | `1` or unset | `dynamic` or unset | unset |
| LinUCB no-A6 | `linucb` | `0` | `dynamic` | unset |
| Constant context | `linucb` | `0` | `constant` | unset |
| Random profile | `random_profile` | `0` | `dynamic` | unset |
| Round-robin profile | `round_robin_profile` | `0` | `dynamic` | unset |
| Static A1 | `static_profile` | `0` | `dynamic` | `1` |
| Static A2 | `static_profile` | `0` | `dynamic` | `2` |
| Static A3 | `static_profile` | `0` | `dynamic` | `3` |
| Static A4 | `static_profile` | `0` | `dynamic` | `4` |
| Static A5 | `static_profile` | `0` | `dynamic` | `5` |

The source validates that non-LinUCB policies use A6=0 and that
`static_profile` has an arm in 1--5. Batch B keeps those checks and does not
add a separate static, random, or round-robin Batch B variant.

The existing `AFL_BANDIT_WINDOW_MS` remains the single window-duration
control. Batch B does not introduce a parallel window variable. Existing
reward, gate, dictionary, CmpLog reward, and verification variables remain
available to these profiles.
