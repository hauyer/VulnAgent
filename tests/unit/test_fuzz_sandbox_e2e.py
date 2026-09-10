from pathlib import Path

import pytest

from vulnagent.contracts import FuzzRequest, EvidenceType
from vulnagent.fuzz.engine import ControlledFuzzEngine


@pytest.mark.asyncio
async def test_fuzz_engine_sandbox_end_to_end(tmp_path: Path):
    """
    Verify the complete fuzz -> executor -> sandbox ->
    runtime trace -> evidence pipeline.
    """

    target = tmp_path / "target.py"

    target.write_text(
        """
import sys

data = sys.stdin.buffer.read()

if b"CRASH" in data:
    sys.exit(-1)

print("input_size:", len(data))
""",
        encoding="utf-8",
    )

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    seed_file = seed_dir / "seed1"
    seed_file.write_bytes(b"hello")

    request = FuzzRequest(
        task_id="e2e-task",
        target_id="e2e-target",
        target_path=str(target),
        authorized=True,
        metadata={
            "seed_dir": str(seed_dir),
        },
    )

    engine = ControlledFuzzEngine(
        timeout_seconds=2.0,
        mutation_count=2,
        seed=0,
    )

    result = await engine.run(request)

    # ---------------------------------------------
    # Fuzz result
    # ---------------------------------------------

    assert result.executed is True
    assert result.task_id == "e2e-task"
    assert result.target_id == "e2e-target"

    assert result.metadata["executions"] > 0

    # ---------------------------------------------
    # Evidence
    # ---------------------------------------------

    assert len(result.evidence) > 0

    evidence_types = {
        item.evidence_type
        for item in result.evidence
    }

    assert EvidenceType.FUZZ_INPUT in evidence_types
    assert EvidenceType.RUNTIME_TRACE in evidence_types
    assert EvidenceType.TOOL_RESULT in evidence_types

    # ---------------------------------------------
    # Runtime Trace
    # ---------------------------------------------

    runtime_evidence = [
        item
        for item in result.evidence
        if item.evidence_type
        == EvidenceType.RUNTIME_TRACE
    ]

    assert len(runtime_evidence) > 0

    for item in runtime_evidence:
        trace = item.data.get(
            "runtime_trace",
            [],
        )

        assert isinstance(trace, list)
