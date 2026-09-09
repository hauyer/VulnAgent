"""Non-executing binary reverse mock."""
from vulnagent.contracts import BinaryAnalysisRequest, BinaryAnalysisResult

class MockBinaryReverseAnalyzer:
    async def analyze(self, request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
        return BinaryAnalysisResult(task_id=request.task_id, target_id=request.target_id, path=request.path, metadata={"mock": True, "executed": False})
