"""Non-scanning mock source analyzer."""

from pathlib import Path
from typing import Any

from vulnagent.analyzers.source.base import BaseSourceAnalyzer


class MockSourceAnalyzer(BaseSourceAnalyzer):
    async def analyze(self, target: Path) -> dict[str, Any]:
        return {"target": str(target), "mock": True, "scanned": False}

