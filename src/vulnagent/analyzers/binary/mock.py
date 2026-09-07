"""Non-executing mock binary analyzer."""

from pathlib import Path
from typing import Any

from vulnagent.analyzers.binary.base import BaseBinaryAnalyzer


class MockBinaryAnalyzer(BaseBinaryAnalyzer):
    async def analyze(self, target: Path) -> dict[str, Any]:
        return {"target": str(target), "mock": True, "executed": False, "scanned": False}

