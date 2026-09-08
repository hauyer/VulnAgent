"""Opt-in P4 workflow; tools are injected and targets are never executed."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Protocol

from vulnagent.contracts import BinaryAnalysisRequest, BinaryAnalysisResult, ModuleExecutionError
from .artifacts import BinaryArtifactStore
from .static import StaticBinaryReverseAnalyzer


class ToolOutcome(Protocol):
    """Private adapter outcome port, not a public contract replacement."""
    status: str
    facts: dict[str, Any] | None
    def as_dict(self) -> dict[str, Any]: ...


class Inspector(Protocol):
    """Optional static reverse tool dependency."""
    def inspect(self, path: str | Path, *, authorized: bool, **options: Any) -> ToolOutcome: ...


class Unpacker(Protocol):
    """Optional file-only unpacking dependency."""
    def unpack(self, path: str | Path, *, output_dir: str | Path, authorized: bool) -> ToolOutcome: ...


class BinaryReverseWorkflow:
    """Compose parsing, optional tools and persistence without changing bootstrap.

    Explicit authorization gates all work. The output root must be private to this
    job. Callers provide sandbox, disk quotas and a single-process writer policy.
    Coroutine cancellation does not kill a tool running in the worker thread.
    """
    def __init__(self, output_root: str | Path, *, inspector: Inspector | None = None,
                 unpacker: Unpacker | None = None) -> None:
        self.root = Path(output_root)
        self.inspector = inspector
        self.unpacker = unpacker

    async def analyze(self, request: BinaryAnalysisRequest, *, authorized: bool = False,
                      unpack: bool = False) -> BinaryAnalysisResult:
        """Persist a result even when an optional tool is missing or fails."""
        if not authorized:
            raise PermissionError("explicit authorization is required")
        result = await StaticBinaryReverseAnalyzer().analyze(request)
        records: list[dict[str, Any]] = []
        tool_input = request.path
        derived: BinaryAnalysisResult | None = None
        if unpack:
            if self.unpacker is None:
                records.append({"tool": "upx", "status": "not_configured"})
            else:
                run = await asyncio.to_thread(self.unpacker.unpack, request.path,
                    output_dir=self.root / "unpacked", authorized=True)
                records.append(run.as_dict())
                if run.status == "ok" and run.facts:
                    candidate = run.facts.get("output_path")
                    if isinstance(candidate, str):
                        try:
                            derived = await StaticBinaryReverseAnalyzer().analyze(
                                request.model_copy(update={"path": candidate}))
                            tool_input = candidate
                        except ModuleExecutionError as exc:
                            records.append({"stage": "parse_unpacked", "status": "error", "error": str(exc)})
        if self.inspector is None:
            records.append({"tool": "reverse", "status": "not_configured"})
        else:
            run = await asyncio.to_thread(self.inspector.inspect, tool_input,
                                           authorized=True, tool_versions=True)
            records.append(run.as_dict())
            if run.status in {"ok", "partial"} and run.facts:
                # A derived image has a distinct address space; do not mix facts.
                destination = derived if derived is not None else result
                destination.functions = run.facts.get("functions", [])
                destination.cfg = run.facts.get("cfg", {})
                destination.metadata["reverse_tool"] = run.facts
        if derived is not None:
            result.metadata["unpacked_analysis"] = derived.model_dump(mode="json")
        result.metadata["tool_runs"] = records
        result.metadata["workflow"] = {"version": 1, "target_executed": False,
            "tool_input": tool_input, "unpack_requested": unpack}
        await asyncio.to_thread(BinaryArtifactStore(self.root).save_result, result)
        return result
