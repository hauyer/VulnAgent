"""Mock fuzzer that cannot execute programs."""

from pathlib import Path
from typing import Any
from vulnagent.contracts import FuzzRequest, FuzzResult
from vulnagent.fuzz.base import BaseFuzzer


class MockFuzzEngine:
    """Contract-compliant engine that never executes a target."""

    async def run(self, request: FuzzRequest) -> FuzzResult:
        return FuzzResult(task_id=request.task_id, target_id=request.target_id, executed=False, crashes=0, metadata={"mock": True, "authorized": request.authorized})


class MockFuzzer(BaseFuzzer):
    """Deprecated compatibility mock for the original Path-based interface."""

    async def run(self, target: Path) -> dict[str, Any]:
        return {"target": str(target), "mock": True, "executed": False, "crashes": 0}
