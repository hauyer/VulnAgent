# Private Ground-Truth Labels

This directory holds the hidden labels referenced by each manifest's
`ground_truth_ref`. It is the **only** place that names a vulnerability, its
location, the patch or a trigger input for held-out/exploratory samples.

## Rules

- The discovery/runtime environment has **no access** to this directory.
- Labels are read by the independent evaluation process **after** the system
  results are frozen; they are never injected into task metadata, prompts or
  agent-visible logs (enforced by `vulnagent.intake.assert_ground_truth_isolated`).
- Label files are not committed. Only this README and the template are tracked.
- Keep one label file per sample and name it exactly as the `ground_truth_ref`
  value (for example `l3-heldout-parser-001.json`).
- For `train` samples the labels may be visible; for `held_out` they must be
  sealed by the evaluation owner before scanning.

Use `ground_truth.TEMPLATE.json` as the starting point.
