"""Workflow integration with synthetic inputs and injected offline tools."""
import json
from pathlib import Path
import pytest
from test_static import make_pe
from vulnagent.contracts import BinaryAnalysisRequest
from vulnagent.analyzers.binary.reverse.adapters import ToolRunResult
from vulnagent.analyzers.binary.reverse.workflow import BinaryReverseWorkflow


async def test_workflow_requires_authorization(tmp_path: Path):
    request = BinaryAnalysisRequest(task_id="t", target_id="x", path="absent")
    with pytest.raises(PermissionError):
        await BinaryReverseWorkflow(tmp_path).analyze(request)
    assert not list(tmp_path.iterdir())


async def test_workflow_persists_missing_tools(tmp_path: Path):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(make_pe())
    request = BinaryAnalysisRequest(task_id="t", target_id="x", path=str(path))
    result = await BinaryReverseWorkflow(tmp_path / "out").analyze(request, authorized=True, unpack=True)
    assert result.cfg == {}
    assert len(result.metadata["tool_runs"]) == 2
    assert json.loads((tmp_path / "out" / "index.json").read_text())["artifacts"]
    assert path.read_bytes() == make_pe()


async def test_workflow_integrates_tool_facts(tmp_path: Path):
    class Inspector:
        def inspect(self, path, **options):
            return ToolRunResult("fake", "ok", facts={"functions": [{"address": 16}], "cfg": {"0x10": ["0x20"]}})
    path = tmp_path / "synthetic.bin"
    path.write_bytes(make_pe())
    request = BinaryAnalysisRequest(task_id="t", target_id="x", path=str(path))
    result = await BinaryReverseWorkflow(tmp_path / "out", inspector=Inspector()).analyze(request, authorized=True)
    assert result.cfg == {"0x10": ["0x20"]}
    assert result.metadata["executed"] is False
