# Target Catalog (Pinned Admission Records)

Version-locked, hashed admission records for the vulnerability-discovery
practice.  Every target is registered here **before** analysis.  The intake
gate (`vulnagent.intake`) is strictly read-only: it never executes a target
and never invokes an analysis tool.

## Layers

| Layer | File / source | Role | Labels |
| --- | --- | --- | --- |
| L0 regression | `l0_regression.yaml` (generated from `benchmarks/manifest.json`) | `train` | visible; fast regression and demos only |
| L1 standard | `l1_juliet.TEMPLATE.yaml` — NIST SARD/Juliet | `train` | visible; rule coverage and false-positive regression |
| L2 historical | `l2_historical.TEMPLATE.yaml` — VulnGym / CVEfixes pinned commits | `validation` | small set for tuning; manually verified |
| L3 held-out | `l3_held_out.TEMPLATE.yaml` — different project/family | `held_out` | sealed; developers cannot read them |
| L4 exploratory | `l4_exploratory.TEMPLATE.yaml` — unlabeled authorized targets | `exploratory` | no preset positive case |

`*.TEMPLATE.yaml` files are starting points and are skipped by the loader.
Copy one, fill it with real values and remove `TEMPLATE` from the name.

## Admission guarantees

1. **Authorization in four dimensions** — `static_read`, `file_transform`,
   `dynamic_run`, `data_export` are independent grants (default deny).
2. **Path boundary** — the resolved target must stay inside an authorized
   root.  Network/UNC/device paths, parent escapes and symlink/junction
   escapes are rejected.
3. **Content pinning** — the SHA-256 of the file or directory tree must
   match the manifest; size limits are enforced.
4. **Label isolation** — `ground_truth_ref` points into the private
   `labels/` directory and must never appear in task metadata, prompts or
   agent-visible logs.

## Regenerate L0

```bash
python scripts/generate_l0_catalog.py
```

## Load and validate a catalog

```python
from pathlib import Path
from vulnagent.intake import DefaultTargetIntake, load_manifest_dir

gate = DefaultTargetIntake()
for manifest in load_manifest_dir(Path("benchmarks/catalog")):
    decision = gate.validate(manifest)
    assert decision.accepted, decision.issues
```
