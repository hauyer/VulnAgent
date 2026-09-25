"""V0.8 Dynamic Confirmation: crash triage / corpus / precheck / backend tests."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from vulnagent.analyzers.source.runtime import RuntimePrecheckAnalyzer
from vulnagent.contracts import ProjectInput
from vulnagent.fuzz import CorpusManager, CrashTriage, PythonFuzzBackend
from vulnagent.fuzz.corpus import SeedGenerator
from vulnagent.fuzz.planner import DynamicValidationPlanner


class _FakeExecution:
    def __init__(self, *, returncode=None, timed_out=False, crashed=False, stderr=b"") -> None:
        self.returncode = returncode
        self.timed_out = timed_out
        self.crashed = crashed
        self.stderr = stderr


def test_triage_classifies_exception() -> None:
    triage = CrashTriage()
    record = triage.classify(
        execution=_FakeExecution(
            returncode=1,
            stderr=b"Traceback (most recent call last):\nZeroDivisionError: division by zero",
        ),
        input_bytes=b"0",
        task_id="t",
        target_id="x",
        run_id="r",
        index=0,
    )
    assert record is not None
    assert record.kind == "exception"
    assert record.exception_class == "ZeroDivisionError"
    assert record.sanitizer_label == "ubsan.divide_by_zero"


def test_triage_classifies_timeout_and_clean() -> None:
    triage = CrashTriage()
    timeout = triage.classify(
        execution=_FakeExecution(timed_out=True), input_bytes=b"1", task_id="t", target_id="x", run_id="r", index=1
    )
    assert timeout is not None and timeout.kind == "timeout"
    clean = triage.classify(
        execution=_FakeExecution(returncode=0), input_bytes=b"1", task_id="t", target_id="x", run_id="r", index=2
    )
    assert clean is None


def test_corpus_deduplicates_and_persists(tmp_path) -> None:
    corpus = CorpusManager()
    assert corpus.add(b"0") is True
    assert corpus.add(b"0") is False
    assert corpus.add_many([b"1", b"1", b"2"]) == 2
    assert corpus.size == 3
    directory = tmp_path / "corpus"
    corpus.save(directory)
    reloaded = CorpusManager()
    assert reloaded.load(directory) == 3
    assert b"0" in reloaded.inputs


def test_seed_generator_matches_sink_shape() -> None:
    candidate = RuntimePrecheckAnalyzer().audit(
        ProjectInput(task_id="t", target_id="x", project_path=str(
            Path(__file__).parent / "data" / "divzero.py"
        ))
    )[0]
    seeds = SeedGenerator().generate(candidate)
    assert b"0" in seeds  # the reproducing input is in the initial corpus


def test_planner_routes_dynamic_sinks() -> None:
    from vulnagent.contracts import VulnerabilityCandidate, VulnerabilityLocation

    candidate = VulnerabilityCandidate(
        vulnerability_id="c1",
        task_id="t",
        title="x",
        vulnerability_type="divide_by_zero",
        cwe_id="CWE-369",
        description="x",
        target_id="x",
        location=VulnerabilityLocation(file_path="a.py", line_start=1, line_end=1),
        source_agent="source_audit",
        source_type="source",
        producer="precheck",
        confidence=0.7,
        severity="WARNING",
        metadata={"sink": "div", "source_kinds": ["numeric_input"]},
    )
    plan = DynamicValidationPlanner().plan(candidate)
    assert plan.strategy == "python-fuzz"
    assert plan.backend == "PythonFuzzBackend"


def test_backend_confirms_real_crash(tmp_path) -> None:
    target = tmp_path / "target.py"
    target.write_text(
        "import sys\n"
        "line = sys.stdin.readline()\n"
        "n = int(line.strip())\n"
        "print(1 // n)\n"
    )
    from vulnagent.contracts import VulnerabilityCandidate, VulnerabilityLocation

    candidate = VulnerabilityCandidate(
        vulnerability_id="c1",
        task_id="t",
        title="div zero",
        vulnerability_type="divide_by_zero",
        cwe_id="CWE-369",
        description="x",
        target_id="x",
        location=VulnerabilityLocation(file_path=str(target), line_start=4, line_end=4),
        source_agent="source_audit",
        source_type="source",
        producer="precheck",
        confidence=0.7,
        severity="WARNING",
        metadata={"sink": "div", "source_kinds": ["numeric_input"]},
    )
    backend = PythonFuzzBackend(seed=0)
    outcome = backend.run_campaign(
        target=target,
        candidate=candidate,
        run_id="r",
        iterations=2,
        timeout_seconds=1.0,
        session_id="s",
        work_dir=tmp_path,
    )
    assert outcome.executed is True
    assert len(outcome.crashes) == 1
    assert outcome.crashes[0].exception_class == "ZeroDivisionError"
    assert outcome.crashes[0].sanitizer_label == "ubsan.divide_by_zero"
    assert any(e.evidence_type.value == "crash_log" for e in outcome.evidence)
    assert outcome.coverage["exceptions"] == 1
