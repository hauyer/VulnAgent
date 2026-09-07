"""Deterministic source audit capability."""
from vulnagent.contracts import SourceAnalysisResult, VulnerabilityCandidate, VulnerabilityLocation
from vulnagent.utils.ids import new_vulnerability_id

class MockSourceAuditor:
    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        return [VulnerabilityCandidate(vulnerability_id=new_vulnerability_id(), task_id=result.task_id, title="Mock unsafe input handling", vulnerability_type="mock_source_finding", description="Synthetic V0.1 source finding; no source code was scanned.", target_id=result.target_id, location=VulnerabilityLocation(file_path=result.project_path), source_agent="source_audit", source_type="source", producer=type(self).__name__, confidence=0.5, severity="INFO", metadata={"mock": True})]
