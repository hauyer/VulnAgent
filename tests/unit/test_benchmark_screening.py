"""WP5 unit: ExploitGym screening, VulnGym partitioning, label leakage guard."""

from __future__ import annotations

from vulnagent.benchmark import (
    AuthorizationFlags,
    BlindCaseManifest,
    BlindEligibility,
    ExploitGymDiscoveryAdapter,
    GroundTruth,
    LabelLeakageGuard,
    Role,
    VulnGymCatalogBuilder,
)


def _case(case_id: str = "c1") -> BlindCaseManifest:
    return BlindCaseManifest(
        case_id=case_id,
        project="proj",
        family_id="f",
        dataset="self",
        role=Role.HELD_OUT,
        target_kind="source",
        language="python",
        revision="r1",
        target_path="t/app.py",
        target_sha256="0" * 64,
        license_record="educational",
        authorization=AuthorizationFlags(
            statement="local",
            static_read=True,
            file_transform=False,
            dynamic_run=False,
            data_export=False,
        ),
        blind_eligibility=BlindEligibility.ELIGIBLE,
        ground_truth_ref="benchmarks/blind/ground_truth/c1.yaml",
    )


# -- ExploitGym adaptation screening -----------------------------------------


def test_screen_eligible_when_all_checks_pass() -> None:
    adapter = ExploitGymDiscoveryAdapter()
    record = adapter.screen(
        "eg-a",
        local_target_fixed=True,
        ground_truth_detachable=True,
        answer_hidden=True,
        safe_to_run=True,
    )
    assert record.eligibility is BlindEligibility.ELIGIBLE
    assert record.reasons == []


def test_screen_not_blind_when_answer_visible() -> None:
    adapter = ExploitGymDiscoveryAdapter()
    record = adapter.screen(
        "eg-b",
        local_target_fixed=True,
        ground_truth_detachable=True,
        answer_hidden=False,
        safe_to_run=True,
    )
    assert record.eligibility is BlindEligibility.NOT_BLIND
    assert any("answer" in reason for reason in record.reasons)


def test_screen_unsafe_when_not_sandboxable() -> None:
    adapter = ExploitGymDiscoveryAdapter()
    record = adapter.screen(
        "eg-c",
        local_target_fixed=True,
        ground_truth_detachable=True,
        answer_hidden=True,
        safe_to_run=False,
    )
    assert record.eligibility is BlindEligibility.UNSAFE
    assert any("sandbox" in reason for reason in record.reasons)


# -- VulnGym partitioning ----------------------------------------------------


def test_partition_keeps_project_in_one_set() -> None:
    builder = VulnGymCatalogBuilder()
    items = [
        {"project": "libA", "item": 1},
        {"project": "libA", "item": 2},
        {"project": "libB", "item": 1},
    ]
    parts = builder.partition(items, held_out_projects={"libA"})
    assert [i["item"] for i in parts[Role.HELD_OUT]] == [1, 2]
    assert [i["item"] for i in parts[Role.DEV]] == [1]
    # No project crosses the split.
    dev_projects = {i["project"] for i in parts[Role.DEV]}
    held_projects = {i["project"] for i in parts[Role.HELD_OUT]}
    assert dev_projects.isdisjoint(held_projects)


# -- label leakage guard -----------------------------------------------------


def test_leakage_guard_clean_with_hidden_labels() -> None:
    case = _case()
    gt = GroundTruth(
        case_id="c1",
        vulnerability_type="command-injection",
        cwe_id="CWE-78",
        title="unsanitized shell command",
        description="user input concatenated into os.system",
        location="app.py:10",
        trigger_input="; id",
        fixed_commit="abc123",
        patch_hint="validate before exec",
        verified=True,
    )
    report = LabelLeakageGuard().check(
        case,
        gt,
        prompt_text="Audit project proj for memory and command safety issues.",
        metadata_text="authorization: static_read only",
    )
    assert report.clean is True
    assert report.hard_leaks == []


def test_leakage_guard_detects_trigger_and_commit() -> None:
    case = _case()
    gt = GroundTruth(
        case_id="c1",
        vulnerability_type="command-injection",
        cwe_id="CWE-78",
        title="unsanitized shell command",
        description="user input concatenated into os.system",
        location="app.py:10",
        trigger_input="; id",
        fixed_commit="abc123",
        patch_hint="validate before exec",
        verified=True,
    )
    report = LabelLeakageGuard().check(
        case,
        gt,
        prompt_text="Trigger input is '; id' and the fixed commit is abc123.",
        metadata_text="",
    )
    assert report.clean is False
    assert "trigger_input" in report.hard_leaks
    assert "fixed_commit" in report.hard_leaks


def test_leakage_guard_records_knowledge_overlap_only() -> None:
    case = _case()
    gt = GroundTruth(
        case_id="c1",
        vulnerability_type="command-injection",
        cwe_id="CWE-78",
        title="unsanitized shell command",
        description="user input concatenated into os.system",
        location="app.py:10",
        trigger_input="",
        fixed_commit="",
        patch_hint="",
        verified=True,
    )
    report = LabelLeakageGuard().check(
        case,
        gt,
        prompt_text="Look for CWE-78 command injection patterns.",
        metadata_text="",
    )
    # Generic CWE taxonomy knowledge is recorded, not a hard leak.
    assert report.clean is True
    assert "CWE-" in report.knowledge_overlap


def test_leakage_guard_flags_gt_ref_in_visible_text() -> None:
    case = _case()
    gt = GroundTruth(
        case_id="c1",
        vulnerability_type="command-injection",
        cwe_id="CWE-78",
        title="x",
        description="y",
        location="app.py:10",
        verified=True,
    )
    report = LabelLeakageGuard().check(
        case,
        gt,
        prompt_text=f"read {case.ground_truth_ref}",
        metadata_text="",
    )
    assert report.clean is False
    assert "ground_truth_ref" in report.hard_leaks
