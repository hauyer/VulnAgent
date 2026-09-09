"""Deterministic source parser used for integration tests."""
from vulnagent.contracts import ProjectInput, SourceAnalysisResult

class MockSourceParser:
    async def analyze(self, request: ProjectInput) -> SourceAnalysisResult:
        return SourceAnalysisResult(task_id=request.task_id, target_id=request.target_id, project_path=request.project_path, metadata={"mock": True, "scanned": False})
