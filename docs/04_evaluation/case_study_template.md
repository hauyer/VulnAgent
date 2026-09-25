# Known-Vulnerability Case Study — TEMPLATE

> One card per known vulnerability.  A PoC here means the **minimum
> observation that proves the defect** (crash, Sanitizer alert, error return,
> test assertion), not an exploit.  Do not include destructive payloads,
> privilege bypass, persistence or lateral-movement steps.

## 1. Identity

- Case id: `case-<nnn>`
- Project / component:
- Vulnerable version / commit (immutable):
- Fixed version / commit (immutable):
- Upstream advisory / fix commit links (with retrieval date):
- CWE:
- License:

## 2. Authorization & environment

- Authorization basis (local / open-source research / written grant):
- Static read / file transform / dynamic run / data export granted (Y/N):
- Isolation used (container / VM / none — static only):
- Toolchain, dependencies, container/image digest:

## 3. Trigger mechanism

- Input entry point (file, function, line):
- Reachability conditions:
- Call chain (each edge links to source/tool evidence):
- Key variable and its data flow:
- Expected check / guard and why it is missing or ineffective:
- Dangerous operation / fault site (file, function, line):

## 4. Minimum non-destructive reproduction

- Input SHA-256 (do not store dangerous plaintext):
- Observation (Sanitizer kind / exception / error / assertion):
- Exit code, log and stack references (evidence ids):
- Same input on the **fixed** version — outcome:
- Reproduction status: `reproduced` / `not_reproduced` / `inconclusive`
  (if not reproduced, state why; never claim verification)

## 5. Why the fix works

- What the fix changes (guard, bound, encoding, API):
- Path/condition that is now blocked:

## 6. Evidence references

| Evidence id | Type | What it shows |
| --- | --- | --- |
|  | source_location / call_path / data_flow / sanitizer_output / ... |  |

## 7. Teaching notes & limitations

- One-sentence root cause:
- Common misread (e.g. treating a dangerous API name as proof):
- Limitations of this analysis:
