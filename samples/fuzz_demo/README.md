# Controlled Fuzz Demo

This self-authored toy target contains a static `eval(input())` marker and
aborts only when it receives the inert `VULNAGENT_CODE_MARKER` boundary probe.
That makes a fixed-budget comparison between generic random mutation and
static-risk-guided mutation observable and reproducible.

It may only be run locally with both `fuzz_authorized=true` and
`dynamic_validation=true`. Execution is time-bounded. The current subprocess
backend records a disabled-network policy but cannot enforce OS-level network
isolation, so only this audited local fixture is allowed. The marker is not an
exploit payload.
