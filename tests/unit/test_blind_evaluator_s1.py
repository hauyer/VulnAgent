"""S1 unit: corrected evaluator semantics.

Table-driven coverage of the eight boundary situations from the acceptance
guide (§10.2), plus root-cause clustering, dataset-from-manifest mapping and
strict vs type-only match policies.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from vulnagent.benchmark import BlindEvaluator
from vulnagent.benchmark.discovery_ports import (
    ExecutionObservation,
    ObservationTriage,
)
from vulnagent.benchmark.schema import (
    AuthorizationFlags,
    BlindCaseManifest,
    DatasetName,
    GroundTruth,
    Role,
    TargetKind,
)

_GT_TPL = """schema_version: 1
case_id: {case_id}
vulnerability_type: {vtype}
cwe_id: {cwe}
title: t
description: d
location: {loc}
trigger_input: ""
fixed_commit: ""
patch_hint: ""
verified: true
"""


def _write_gt(gt_dir: Path, case_id: str, vtype: str, cwe: str, loc: str) -> None:
    gt_dir.mkdir(parents=True, exist_ok=True)
    (gt_dir / f"{case_id}.yaml").write_text(
        _GT_TPL.format(case_id=case_id, vtype=vtype, cwe=cwe, loc=loc),
        encoding="utf-8",
    )


def _write_candidates(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    path.write_text(text, encoding="utf-8")


def _row(
    case_id: str,
    *,
    vtype: str = "crash",
    cwe: str = "CWE-476",
    loc: str = "a.c:1",
    cluster: str = "",
    count: int = 1,
) -> dict:
    return {
        "case_id": case_id,
        "candidate_id": f"{case_id}-{cluster or 'x'}",
        "vulnerability_type": vtype,
        "cwe_id": cwe,
        "location": loc,
        "root_cause_cluster": cluster,
        "raw_crash_count": count,
        "status": "success",
        "note": "test",
    }


# ① One GT, one matching candidate -> TP.
def test_situation_1_one_gt_one_match(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row("a", vtype="crash", cwe="CWE-476", loc="a.c:10")],
    )
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (1, 0, 0)
    assert r.precision == 1.0 and r.recall == 1.0
    assert r.per_case[0].match_basis.value == "exact_location"


# ② One GT, two distinct candidates, one is a false positive.
def test_situation_2_one_gt_two_candidates(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(
        tmp_path / "c.jsonl",
        [
            _row("a", vtype="crash", cwe="CWE-476", loc="a.c:10", cluster="k1"),
            _row("a", vtype="other", cwe="CWE-999", loc="b.c:1", cluster="k2"),
        ],
    )
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (1, 1, 0)
    assert r.precision == 0.5 and r.recall == 1.0


# ③ 27 crash inputs sharing one root cause form ONE candidate.
def test_situation_3_cluster_collapses_raw_crashes(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    # The triage pass emits ONE row per cluster carrying the cluster total.
    rows = [
        _row("a", vtype="crash", cwe="CWE-476", loc="a.c:10", cluster="same", count=27)
    ]
    # Multiple rows sharing a cluster must collapse to one unique candidate
    # (e.g. a re-triage or duplicate emission) without double counting.
    rows.append(
        _row("a", vtype="crash", cwe="CWE-476", loc="a.c:10", cluster="same", count=27)
    )
    _write_candidates(tmp_path / "c.jsonl", rows)
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (1, 0, 0)
    assert r.per_case[0].n_candidates == 1
    assert r.per_case[0].raw_crashes == 27  # max, not summed


# ④ Two GTs, only one hit -> FN = 1.
def test_situation_4_two_gt_one_hit(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_gt(tmp_path / "gt", "b", "overflow", "CWE-121", "b.c:4")
    _write_candidates(tmp_path / "c.jsonl", [_row("a", vtype="crash", cwe="CWE-476", loc="a.c:10")])
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (1, 0, 1)
    assert r.recall == 0.5


# ⑤ Fixed version (no GT) producing candidates -> FP > 0.
def test_situation_5_fixed_version_candidates_are_fp(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row("fixed-a", vtype="crash", cwe="CWE-476", loc="a.c:10")],
    )
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert r.fp == 1
    assert r.case_fp == 1


# ⑥ GT present but no candidate -> FN.
def test_situation_6_gt_without_candidate_is_fn(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(tmp_path / "c.jsonl", [])
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (0, 0, 1)
    assert r.recall == 0.0


# ⑦ No GT and no candidate: kept in the denominator as TN; P/R stay undefined.
def test_situation_7_clean_case_kept_in_denominator(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(tmp_path / "c.jsonl", [_row("a", vtype="crash", cwe="CWE-476", loc="a.c:10")])
    r = BlindEvaluator().evaluate(
        tmp_path / "c.jsonl", tmp_path / "gt",
        all_case_ids=["a", "clean-1", "clean-2"],
    )
    assert r.total_targets == 3
    assert r.case_tn == 2
    assert r.per_case[0].tn is False
    tn_rows = [o for o in r.per_case if o.tn]
    assert len(tn_rows) == 2
    # Precision/recall only over evaluable units; TN rows never make P/R 1.0.
    assert r.precision == 1.0 and r.recall == 1.0


# ⑦b No GT, no candidate, NOTHING evaluable -> precision/recall undefined.
def test_situation_7b_all_clean_precision_undefined(tmp_path: Path) -> None:
    _write_candidates(tmp_path / "c.jsonl", [])
    r = BlindEvaluator().evaluate(
        tmp_path / "c.jsonl", tmp_path / "gt",
        all_case_ids=["clean-1", "clean-2"],
    )
    assert r.total_targets == 2
    assert r.case_tn == 2
    assert r.precision is None and r.recall is None
    assert r.case_precision is None and r.case_recall is None


# ⑧ Build failure / timeout: excluded from evaluable, kept in total + failure table.
def test_situation_8_build_failure_kept_explicit(tmp_path: Path) -> None:
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row_with_status("a", "unavailable", "toolchain missing")],
    )
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert r.total_targets == 1
    assert r.evaluable_cases == 0
    assert r.excluded and "unavailable" in r.excluded[0]


def _row_with_status(case_id: str, status: str, note: str = "") -> dict:
    return {
        "case_id": case_id,
        "candidate_id": f"{case_id}-s",
        "vulnerability_type": "",
        "cwe_id": "",
        "location": "",
        "status": status,
        "note": note,
    }


def test_strict_policy_type_only_is_fp_and_fn(tmp_path: Path) -> None:
    """Type matches but file does not: strict -> explicit FP + FN."""
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row("a", vtype="crash", cwe="CWE-476", loc="other.c:1")],
    )
    strict = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (strict.tp, strict.fp, strict.fn) == (0, 1, 1)
    relaxed = BlindEvaluator().evaluate(
        tmp_path / "c.jsonl", tmp_path / "gt", match_policy="type_only_allowed"
    )
    assert (relaxed.tp, relaxed.fp, relaxed.fn) == (1, 0, 0)
    assert relaxed.per_case[0].match_basis.value == "type_only"
    assert relaxed.per_case[0].loc_error == 1.0


def test_same_file_counts_as_match_with_basis(tmp_path: Path) -> None:
    """Same file, line unknown in GT (line 0) -> same_file match."""
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:0")
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row("a", vtype="crash", cwe="CWE-476", loc="a.c:12")],
    )
    r = BlindEvaluator().evaluate(tmp_path / "c.jsonl", tmp_path / "gt")
    assert (r.tp, r.fp, r.fn) == (1, 0, 0)
    assert r.per_case[0].match_basis.value == "same_file"
    assert r.avg_loc_error == 0.0  # GT line unknown: same file is the best claim


def test_dataset_comes_from_manifest_not_hardcoded(tmp_path: Path) -> None:
    """CaseOutcome.dataset maps from the frozen manifest, never 'self'."""
    _write_gt(tmp_path / "gt", "a", "crash", "CWE-476", "a.c:10")
    _write_candidates(tmp_path / "c.jsonl", [_row("a", vtype="crash", cwe="CWE-476", loc="a.c:10")])
    manifest = BlindCaseManifest(
        case_id="a",
        project="quickjs",
        family_id="nofuzz",
        dataset=DatasetName.EXPLOITGYM_ADAPTED,
        role=Role.DEV,
        target_kind=TargetKind.BINARY,
        language="c",
        revision="rev",
        target_path="tp",
        target_sha256="",
        license_record="L",
        authorization=AuthorizationFlags(
            statement="s", static_read=True, file_transform=False,
            dynamic_run=True, data_export=False,
        ),
        ground_truth_ref="gt/a.yaml",
    )
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "a.json").write_text(
        manifest.model_dump_json(), encoding="utf-8"
    )
    r = BlindEvaluator().evaluate(
        tmp_path / "c.jsonl", tmp_path / "gt",
        manifest_dir=tmp_path / "manifests",
    )
    assert r.per_case[0].dataset is DatasetName.EXPLOITGYM_ADAPTED


def test_opaque_candidate_rows_remap_to_dataset_case(tmp_path: Path) -> None:
    """Candidates written under the de-identified opaque handle join the GT
    case through the manifest's opaque_case_id -> case_id bridge."""
    _write_gt(tmp_path / "gt", "CVE-2030-0001", "crash", "CWE-476", "a.c:10")
    # The discovery process only knows the opaque handle.
    _write_candidates(
        tmp_path / "c.jsonl",
        [_row("eg-blind-opaque-001", vtype="crash", cwe="CWE-476", loc="a.c:10")],
    )
    manifest = BlindCaseManifest(
        case_id="CVE-2030-0001",
        opaque_case_id="eg-blind-opaque-001",
        project="quickjs",
        family_id="nofuzz",
        dataset=DatasetName.EXPLOITGYM_ADAPTED,
        role=Role.DEV,
        target_kind=TargetKind.BINARY,
        language="c",
        revision="rev",
        target_path="tp",
        target_sha256="",
        license_record="L",
        authorization=AuthorizationFlags(
            statement="s", static_read=True, file_transform=False,
            dynamic_run=True, data_export=False,
        ),
        ground_truth_ref="gt/a.yaml",
    )
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "a.json").write_text(
        manifest.model_dump_json(), encoding="utf-8"
    )
    r = BlindEvaluator().evaluate(
        tmp_path / "c.jsonl", tmp_path / "gt",
        manifest_dir=tmp_path / "manifests",
    )
    # The opaque-keyed row joined the GT case: one TP, no phantom row on the
    # opaque id, no second per-case entry.
    assert r.tp == 1 and r.fp == 0 and r.fn == 0
    assert len(r.per_case) == 1
    assert r.per_case[0].case_id == "CVE-2030-0001"
    assert r.per_case[0].match_basis.value in {"exact_location", "same_file"}


def test_observation_triage_clusters_by_root_cause() -> None:
    obs = [
        ExecutionObservation(
            input_sha256="a" * 64, target_sha256="b" * 64,
            exit_code=0xC0000005, timed_out=False, crashed=True,
            sanitizer_kind=None, stack_frames=("q.c:10",),
            stderr_artifact=None, isolation_capabilities=frozenset(),
        ),
        ExecutionObservation(
            input_sha256="c" * 64, target_sha256="b" * 64,
            exit_code=0xC0000005, timed_out=False, crashed=True,
            sanitizer_kind=None, stack_frames=("q.c:10",),
            stderr_artifact=None, isolation_capabilities=frozenset(),
        ),
        ExecutionObservation(
            input_sha256="d" * 64, target_sha256="b" * 64,
            exit_code=0xC0000005, timed_out=False, crashed=True,
            sanitizer_kind=None, stack_frames=("r.c:3",),
            stderr_artifact=None, isolation_capabilities=frozenset(),
        ),
    ]
    clusters = ObservationTriage.cluster(obs, run_id="t")
    assert len(clusters) == 2  # two distinct root causes
    by_frame = {c.top_frame: c for c in clusters}
    assert len(by_frame["q.c:10"].observation_hashes) == 2


def test_spec_carries_no_answer_fields() -> None:
    """The de-identified spec must not contain CVE/CWE/patch/GT references."""
    from dataclasses import asdict

    from vulnagent.benchmark.discovery_ports import AgentTargetSpec

    spec = AgentTargetSpec(
        opaque_case_id="eg-blind-opaque-001",
        target_path=Path("qjs_asan.exe"),
        target_sha256="h" * 64,
        seed_dir=Path("seeds"),
        time_budget_seconds=60,
        max_executions=10,
    )
    text = json.dumps(
        {
            key: str(value)
            for key, value in asdict(spec).items()
        }
    )
    for forbidden in ("CVE", "CWE", "build_for_in_iterator", "ground_truth", "fixed_commit"):
        assert forbidden not in text
