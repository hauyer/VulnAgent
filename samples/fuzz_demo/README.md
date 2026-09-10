# Controlled Fuzz Demo

This toy target intentionally aborts on non-empty standard input. It may only
be run locally with both `fuzz_authorized=true` and `dynamic_validation=true`.
Execution is time-bounded and network access is disabled by policy.
