"""Unit tests for P7 deterministic finding deduplication (verification boundary)."""

from vulnagent.contracts import Target, TargetType, Task, VulnerabilityCandidate, VulnerabilityLocation
from vulnagent.verification.duplicate import deduplicate, partition_duplicates


def make_candidate(
    vulnerability_id: str,
    *,
    target_id: str = "target-1",
    vulnerability_type: str = "command_injection",
    location: VulnerabilityLocation | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id="task-1",
        title="Potential command injection",
        vulnerability_type=vulnerability_type,
        description="User input may reach an unsafe sink.",
        target_id=target_id,
        location=location or VulnerabilityLocation(file_path="a.c", function_name="parse", line_start=1, line_end=2),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
    )


def test_deduplicate_removes_exact_duplicates_preserving_first() -> None:
    a = make_candidate("v1")
    b = make_candidate("v2")  # same target/type/location -> duplicate of v1
    c = make_candidate("v3", location=VulnerabilityLocation(file_path="b.c", function_name="send", line_start=9, line_end=12))
    result = deduplicate([a, b, c])
    assert [item.vulnerability_id for item in result] == ["v1", "v3"]


def test_deduplicate_keeps_distinct_types_and_locations() -> None:
    a = make_candidate("v1", vulnerability_type="command_injection")
    b = make_candidate("v2", vulnerability_type="sql_injection")  # same location, different kind
    c = make_candidate("v3", location=VulnerabilityLocation(file_path="a.c", function_name="parse", line_start=20, line_end=25))
    assert [item.vulnerability_id for item in deduplicate([a, b, c])] == ["v1", "v2", "v3"]


def test_deduplicate_keeps_distinct_targets() -> None:
    a = make_candidate("v1", target_id="target-1")
    b = make_candidate("v2", target_id="target-2")  # same kind/location, different target
    assert [item.vulnerability_id for item in deduplicate([a, b])] == ["v1", "v2"]


def test_partition_duplicates_reports_dropped_candidates() -> None:
    a = make_candidate("v1")
    b = make_candidate("v2")
    c = make_candidate("v3", location=VulnerabilityLocation(file_path="b.c", function_name="send", line_start=9, line_end=12))
    unique, duplicates = partition_duplicates([a, b, c])
    assert [item.vulnerability_id for item in unique] == ["v1", "v3"]
    assert [item.vulnerability_id for item in duplicates] == ["v2"]


def test_deduplicate_is_empty_safe() -> None:
    assert deduplicate([]) == []
    unique, duplicates = partition_duplicates([])
    assert unique == [] and duplicates == []


def test_task_import_smoke() -> None:
    """Guard: fixtures remain compatible with the public Task contract."""
    task = Task(task_id="task-1", target=Target(target_id="target-1", path="proj", target_type=TargetType.SOURCE))
    assert task.task_id == "task-1"
