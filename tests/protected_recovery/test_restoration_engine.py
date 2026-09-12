"""End-to-end restoration orchestration with a recorded isolated snapshot."""

from pathlib import Path

from vulnagent.analyzers.binary.restoration import (
    ApiResolution,
    MemoryRegion,
    MemorySnapshot,
    PEImageRebuilder,
    ProgramRestorationEngine,
    RecordedSnapshotProvider,
)
from vulnagent.contracts import BinaryAnalysisRequest


async def test_dynamic_snapshot_is_rebuilt_and_reparsed(tmp_path: Path) -> None:
    protected = MemorySnapshot(
        image_base=0x400000,
        entry_point=0x401000,
        bits=32,
        machine=0x14C,
        regions=(
            MemoryRegion(0x401000, b"\x90VMProtect demo\0\xC3", executable=True, name=".vmp0"),
        ),
    )
    source = tmp_path / "teaching-protected.exe"
    source.write_bytes(PEImageRebuilder().rebuild(protected).data)

    captured = MemorySnapshot(
        image_base=0x400000,
        entry_point=0x401000,
        bits=32,
        machine=0x14C,
        regions=(
            MemoryRegion(0x401000, b"\x90\x90\xC3", executable=True, name=".text"),
        ),
        api_resolutions=(ApiResolution("KERNEL32.dll", "ExitProcess"),),
        capture_evidence={"fixture": "instructor-recorded", "oep_score": 0.94},
    )
    engine = ProgramRestorationEngine(
        tmp_path / "artifacts",
        snapshot_provider=RecordedSnapshotProvider(captured),
    )
    result = await engine.restore(
        BinaryAnalysisRequest(task_id="task-restoration", target_id="target", path=str(source)),
        authorized=True,
        dynamic_authorized=True,
    )

    assert result["success"] is True
    assert result["protection"]["selected"]["code"] == "vmprotect_demo"
    assert result["validation"]["parseable"] is True
    assert result["validation"]["imports"] == 1
    assert Path(result["output_path"]).is_file()
    assert result["records"][0]["capture_evidence"]["oep_score"] == 0.94
