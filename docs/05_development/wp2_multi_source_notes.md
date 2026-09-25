# WP2 Static Multi-Source — Delivery Notes

> WP2 goal (per the development guide): register real external engines, keep
> real runs separate from mocks, fuse Native + Semgrep + Bandit candidates
> into one candidate per flaw, and never report a missing tool as zero
> findings. All numbers below were produced by the real commands on this host.

## What changed

### 1. External scanners are now real registered capabilities

- `CapabilityName` gains `source.scan.semgrep` and `source.scan.bandit`.
- `CapabilityBundle` gains optional `semgrep_adapter` / `bandit_adapter`
  (default `None`); when `None`, `build_tool_registry` still binds the real
  fail-safe `SemgrepAdapter()` / `BanditAdapter()` so every profile exposes the
  full capability set without executing anything at composition time.
- `build_tool_registry` registers both as `capability_type="source"` with
  descriptions stating that a missing engine is reported as `unavailable`,
  never as zero findings.
- Mock and v03-source applications both register the same 10 capabilities;
  the dependency-injection test was updated from 8 to 10 expected names.

### 2. Honest status vocabulary (`src/vulnagent/adapters/normalize.py`)

`tool_result_status(result)` maps a `ToolExecutionResult` onto one of:

| status | meaning |
| --- | --- |
| `ok` | engine really ran and produced findings |
| `empty` | engine really ran and found nothing |
| `unavailable` | engine could not run (missing executable / module) |
| `timeout` | engine was killed by the budget |
| `error` | engine ran but failed (bad JSON, engine error exit) |
| `blocked` | run refused earlier (e.g. target missing) |

A missing tool is detected via `not found` / `No module named` signals and
classified `unavailable` with `success=False` — it never looks like a scan
that found nothing.

### 3. External finding -> candidate normalization

`external_finding_to_candidate(...)` converts a `NormalizedToolFinding` into a
`VulnerabilityCandidate` (status stays `CANDIDATE`, `source_type="external_tool"`).
Fingerprint components are carried in metadata:

- `cwe_id` reduced to the canonical `CWE-N` (Semgrep returns long
  descriptions such as `CWE-78: Improper Neutralization ...`; the regex keeps
  the id so engines agree).
- `sink` derived from the finding: explicit raw sink -> Semgrep-style message
  (`Found 'subprocess' function 'run' ...` -> `subprocess.run`) -> last call in
  a Bandit code snippet -> bare function mention.

### 4. Multi-engine experiment runner

`experiments/run_external_scanners.py` runs Native + Semgrep + Bandit over
every admitted L0 catalog target and writes:

- `tool_runs.jsonl` — one honest-status record per engine per sample
  (run_id, capability, provider, status, counts, elapsed, sample, input hash)
- `candidates.jsonl` — every external finding as a candidate
- `fused_candidates.jsonl` — fused candidates with independence groups per engine
- `rows.json` — per-sample summary (expected from the benchmark manifest,
  observed from the native auditor; external results feed the fusion)

## Verification results (this host, 2026-09-25)

- Full gate: **693 passed, 1 skipped** (up from 667 in WP0); `npm run lint` passes.
- Bandit 1.9.4 and Semgrep (CLI via `python -m semgrep`) are installed and
  really executed; no `unavailable` runs occurred on this host.
- Tool-run status distribution over 20 L0 samples: 40 runs,
  semgrep `ok=5 / empty=15`, bandit `ok=9 / empty=11`.
- Fusion: the strongest case (`py-cmd-001-vulnerable`) fused all three engines
  (`bandit+native+semgrep`, 3 sources, one candidate); 5 fused candidates had
  >= 2 independent engines; clean samples stayed clean (no false positives
  from the native auditor).
- Semgrep SQL-audit rules carry no sink call in their message; those findings
  fuse only among themselves (same CWE + location) and do not merge with the
  sink-bearing bandit/native candidates. This is the conservative choice:
  missing fingerprint components never force a merge.

## Honest reporting rule (enforced)

A missing engine is `unavailable`, not "0 findings". This is enforced by
`tool_result_status` and by the integration test
`tests/adapters/test_wp2_registry.py`, which asserts that a non-successful
(unavailable) engine run must never produce findings.

## Limitations / next steps

- The SQL sample shows the conservative fusion boundary when an engine omits
  sink info; a follow-up could align Semgrep audit rules with sink extraction.
- `observed` in `rows.json` currently reflects the native auditor; external
  findings are recorded separately. A verification-enabled arm (WP3/WP4) will
  confirm/reject the fused candidates.
- Artifacts live under `artifacts/experiments/wp2-multi-engine/` (regenerate
  with `python -m experiments.run_external_scanners`).
