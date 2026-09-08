import os
import stat
from pathlib import Path

import pytest

from vulnagent.contracts import FuzzRequest
from vulnagent.fuzz.engine import ControlledFuzzEngine


def create_test_target(path: Path) -> None:
    code = """#!/usr/bin/env python3
import sys

data = sys.stdin.buffer.read()

if b"CRASH" in data:
    raise RuntimeError("intentional test crash")

print("OK")
"""

    path.write_text(
        code,
        encoding="utf-8",
    )

    current_mode = path.stat().st_mode

    path.chmod(
        current_mode
        | stat.S_IXUSR
        | stat.S_IXGRP
        | stat.S_IXOTH
    )


@pytest.mark.asyncio
async def test_unauthorized_target_is_not_executed(
    tmp_path: Path,
) -> None:

    target = tmp_path / "target.py"

    create_test_target(target)

    request = FuzzRequest(
        task_id="task-test",
        target_id="target-test",
        target_path=str(target),
        authorized=False,
    )

    engine = ControlledFuzzEngine()

    result = await engine.run(request)

    assert result.executed is False
    assert result.crashes == 0


@pytest.mark.asyncio
async def test_fuzz_engine_runs_authorized_target(
    tmp_path: Path,
) -> None:

    target = tmp_path / "target.py"

    create_test_target(target)

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    (seed_dir / "seed1").write_bytes(
        b"hello"
    )

    request = FuzzRequest(
        task_id="task-test",
        target_id="target-test",
        target_path=str(target),
        authorized=True,
        time_budget_seconds=1,
        metadata={
            "seed_dir": str(seed_dir),
        },
    )

    engine = ControlledFuzzEngine(
        timeout_seconds=1,
        mutation_count=4,
        seed=123,
    )

    result = await engine.run(request)

    assert result.executed is True
    assert result.metadata["executions"] == 4
    assert len(result.evidence) > 0