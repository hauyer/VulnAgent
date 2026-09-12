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

    async def analyze(
        self,
        request: BinaryAnalysisRequest,
        *,
        authorized: bool = False,
        unpack: bool = False,
        auto_unpack: bool = False,
    ) -> BinaryAnalysisResult:
        """Plan and persist a bounded reverse-analysis result.

        ``auto_unpack`` is deliberately narrow: it selects UPX transformation
        only when the structural parser observed an explicit UPX section
        marker.  Other protectors remain read-only and are reported as such.
        """
        if not authorized:
            raise PermissionError("explicit authorization is required")
        result = await StaticBinaryReverseAnalyzer().analyze(request)
        records: list[dict[str, Any]] = []
        tool_input = request.path
        derived: BinaryAnalysisResult | None = None
        upx_signal = _has_upx_signal(result)
        effective_unpack = unpack or (auto_unpack and upx_signal)
        plan: dict[str, Any] = {
            "version": 1,
            "planner": "binary-reverse-workflow",
            "authorization_confirmed": True,
            "target_executed": False,
            "decisions": {
                "upx_signal_observed": upx_signal,
                "unpack_requested": unpack,
                "auto_unpack_enabled": auto_unpack,
                "unpack_selected": effective_unpack,
                "decompile_selected": self.inspector is not None,
                "semantic_analysis_selected": True,
            },
            "steps": [
                {"stage": "structural_parse", "status": "completed"},
                {
                    "stage": "unpack",
                    "status": "scheduled" if effective_unpack else "not_required",
                    "reason": (
                        "explicit request or UPX section marker"
                        if effective_unpack
                        else "no explicit UPX marker; preserve original image"
                    ),
                },
                {
                    "stage": "decompile",
                    "status": "scheduled" if self.inspector is not None else "not_configured",
                },
                {"stage": "semantic_logic", "status": "scheduled"},
                {"stage": "vulnerability_rules", "status": "scheduled"},
                {"stage": "independent_verification", "status": "scheduled"},
            ],
        }
        if effective_unpack:
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
        if effective_unpack:
            unpack_record = next(
                (item for item in records if item.get("tool") == "upx"),
                None,
            )
            _set_stage_status(
                plan,
                "unpack",
                "completed" if derived is not None else str((unpack_record or {}).get("status", "failed")),
            )
        reverse_record = next(
            (
                item
                for item in reversed(records)
                if item.get("tool") in {"radare2", "reverse"}
            ),
            None,
        )
        if reverse_record is not None:
            reverse_status = str(reverse_record.get("status", "failed"))
            _set_stage_status(
                plan,
                "decompile",
                "completed" if reverse_status in {"ok", "partial"} else reverse_status,
            )
        result.metadata["tool_runs"] = records
        result.metadata["analysis_plan"] = plan
        result.metadata["workflow"] = {
            "version": 2,
            "target_executed": False,
            "tool_input": tool_input,
            "unpack_requested": unpack,
            "auto_unpack_enabled": auto_unpack,
            "unpack_selected": effective_unpack,
            "unpacked_artifact_created": derived is not None,
        }
        await asyncio.to_thread(BinaryArtifactStore(self.root).save_result, result)
        return result


def _has_upx_signal(result: BinaryAnalysisResult) -> bool:
    """Return true only for an explicit UPX marker from structural facts."""

    packing = result.metadata.get("packing_signals")
    if not isinstance(packing, dict):
        return False
    section_signals = packing.get("section_signals")
    if not isinstance(section_signals, list):
        return False
    return any(
        isinstance(item, dict)
        and str(item.get("packer_marker", "")).casefold() == "upx"
        for item in section_signals
    )


def _set_stage_status(plan: dict[str, Any], stage: str, status: str) -> None:
    """Update one public plan stage without assuming a fixed list position."""

    steps = plan.get("steps")
    if not isinstance(steps, list):
        return
    for item in steps:
        if isinstance(item, dict) and item.get("stage") == stage:
            item["status"] = status
            return
