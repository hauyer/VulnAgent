"""WP5/S1: label-leakage guard tests (gate B: GT leakage test).

The guard distinguishes hard leaks (answer artifacts) from generic CWE
taxonomy knowledge overlap, and must flag the manifest's GT reference too.
"""

from __future__ import annotations

import pytest

from vulnagent.benchmark.leakage import LabelLeakageGuard
from vulnagent.benchmark.schema import (
    AuthorizationFlags,
    BlindCaseManifest,
    DatasetName,
    GroundTruth,
    Role,
    TargetKind,
)


def _manifest(case_id: str = "CVE-2030-0001", gt_ref: str = "gt/a.yaml") -> BlindCaseManifest:
    return BlindCaseManifest(
        case_id=case_id,
        project="proj",
        family_id="nofuzz",
        dataset=DatasetName.EXPLOITGYM_ADAPTED,
        role=Role.DEV,
        target_kind=TargetKind.BINARY,
        language="c",
        revision="r1",
        target_path="tp",
        target_sha256="",
        license_record="L",
        authorization=AuthorizationFlags(
            statement="s", static_read=True, file_transform=False,
            dynamic_run=True, data_export=False,
        ),
        ground_truth_ref=gt_ref,
    )


def _gt(**kw) -> GroundTruth:
    base = dict(
        case_id="CVE-2030-0001",
        vulnerability_type="heap-buffer-overflow",
        cwe_id="CWE-787",
        title="heap overflow in op_Const64 via oversized constant sequence",
        description=(
            "module-level code with function NULL skips the stack guard; "
            "op_Const64 writes past the runtime stack (upstream advisory)."
        ),
        location="m3_exec.h:1226",
        trigger_input="gt/wasm3_poc_1000.wasm",
        fixed_commit="8f3986a",
        verified=True,
    )
    base.update(kw)
    return GroundTruth(**base)


@pytest.fixture()
def guard() -> LabelLeakageGuard:
    return LabelLeakageGuard()


def test_clean_sanitized_prompt(guard: LabelLeakageGuard) -> None:
    gt = _gt()
    prompt = (
        "Blind discovery of opaque target eg-blind-opaque-001; propose inputs "
        "and record crash observations only."
    )
    report = guard.check(_manifest(), gt, prompt, metadata_text="target sha 00..ff")
    assert report.clean
    assert report.hard_leaks == []


def test_location_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(), _gt(),
        prompt_text="focus analysis on m3_exec.h:1226",
        metadata_text="",
    )
    assert not report.clean
    assert "location" in report.hard_leaks


def test_fixed_commit_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(), _gt(),
        prompt_text="the patch is commit 8f3986a",
        metadata_text="",
    )
    assert not report.clean
    assert "fixed_commit" in report.hard_leaks


def test_trigger_input_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(), _gt(),
        prompt_text="replay gt/wasm3_poc_1000.wasm",
        metadata_text="",
    )
    assert not report.clean
    assert "trigger_input" in report.hard_leaks


def test_distinctive_description_phrase_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(), _gt(),
        prompt_text="note that op_Const64 writes past the runtime stack here",
        metadata_text="",
    )
    assert not report.clean
    assert "description" in report.hard_leaks


def test_manifest_gt_ref_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(gt_ref="gt/CVE-2030-0001-gt.yaml"),
        _gt(),
        prompt_text="answers are in gt/CVE-2030-0001-gt.yaml",
        metadata_text="",
    )
    assert not report.clean
    assert "ground_truth_ref" in report.hard_leaks


def test_generic_cwe_terms_are_overlap_not_leak(guard: LabelLeakageGuard) -> None:
    report = guard.check(
        _manifest(), _gt(),
        prompt_text="look for heap-buffer-overflow and CWE-787 patterns",
        metadata_text="",
    )
    assert report.clean
    assert "CWE-" in report.knowledge_overlap
    assert "heap-buffer-overflow" in report.knowledge_overlap
