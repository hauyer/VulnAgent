"""Obfuscation feature mock consuming only BinaryAnalysisResult."""
from typing import Any
from vulnagent.contracts import BinaryAnalysisResult

class MockObfuscationAnalyzer:
    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, Any]:
        return {"target_id": result.target_id, "obfuscated": False, "mock": True}
