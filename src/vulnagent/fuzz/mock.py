"""Mock fuzzer that cannot execute programs."""

from pathlib import Path
from typing import Any

from vulnagent.fuzz.base import BaseFuzzer


class MockFuzzer(BaseFuzzer):
    async def run(self, target: Path) -> dict[str, Any]:
        return {"target": str(target), "mock": True, "executed": False, "crashes": 0}

