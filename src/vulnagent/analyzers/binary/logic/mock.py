"""Business-logic locator mock consuming only BinaryAnalysisResult."""
from typing import Any
from vulnagent.contracts import BinaryAnalysisResult

class MockLogicAnalyzer:
    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, Any]:
        return {"target_id": result.target_id, "locations": [], "mock": True}
