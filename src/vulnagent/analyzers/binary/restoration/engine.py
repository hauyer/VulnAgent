"""Authorization-gated strategy engine for PE and DEX restoration."""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from time import monotonic
from typing import Any, Protocol

from vulnagent.contracts import BinaryAnalysisRequest, BinaryAnalysisResult

from ..protection import classify_protection
from ..reverse._dex import is_apk, is_dex, repair_dex_header
from ..reverse.static import StaticBinaryReverseAnalyzer
from .dynamic import FridaDexSnapshotProvider, WindowsDebugSnapshotProvider
from .pe_rebuild import PEImageRebuilder


class StaticUnpacker(Protocol):
    def unpack(self, path: str | Path, *, output_dir: str | Path, authorized: bool) -> Any: ...


class ProgramRestorationEngine:
    """Select and validate restoration without silently claiming unsupported work."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        static_unpacker: StaticUnpacker | None = None,
        snapshot_provider: WindowsDebugSnapshotProvider | None = None,
        dex_provider: FridaDexSnapshotProvider | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.output_root = Path(output_root)
        self.static_unpacker = static_unpacker
        self.snapshot_provider = snapshot_provider
        self.dex_provider = dex_provider
        self.timeout_seconds = timeout_seconds
        self.analyzer = StaticBinaryReverseAnalyzer()
        self.rebuilder = PEImageRebuilder()

    async def restore(
        self,
        request: BinaryAnalysisRequest,
        *,
        authorized: bool = False,
        dynamic_authorized: bool = False,
        emulator_serial: str | None = None,
    ) -> dict[str, Any]:
        """Return an auditable plan, artifacts, metrics and parser validation."""

        if not authorized:
            raise PermissionError("program restoration requires explicit authorization")
        started = monotonic()
        baseline = await self.analyzer.analyze(request)
        assessment = baseline.metadata.get("protection_analysis") or classify_protection(baseline)
        selected = assessment.get("selected") if isinstance(assessment, dict) else None
        code = str(selected.get("code", "")) if isinstance(selected, dict) else ""
        records: list[dict[str, Any]] = []
        output_paths: list[str] = []
        selected_path = request.path
        strategy = list(assessment.get("strategy", [])) if isinstance(assessment, dict) else []

        if baseline.file_format in {"DEX", "APK"}:
            dex_record = await self._restore_dex(
                request,
                dynamic_authorized=dynamic_authorized,
                emulator_serial=emulator_serial,
            )
            records.append(dex_record)
            output_paths.extend(dex_record.get("output_paths", []))
            if output_paths:
                selected_path = output_paths[0]
        elif code == "upx" and self.static_unpacker is not None:
            record = await asyncio.to_thread(
                self.static_unpacker.unpack,
                request.path,
                output_dir=self._job_dir(request.task_id) / "static",
                authorized=True,
            )
            item = record.as_dict()
            records.append(item)
            candidate = item.get("facts", {}).get("output_path") if isinstance(item.get("facts"), dict) else None
            if isinstance(candidate, str) and record.status == "ok":
                selected_path = candidate
                output_paths.append(candidate)
        elif isinstance(selected, dict) and dynamic_authorized:
            if self.snapshot_provider is None:
                records.append({
                    "stage": "dynamic_snapshot",
                    "status": "not_configured",
                    "reason": "isolated Windows Debug API provider is not configured",
                })
            else:
                snapshot = await self.snapshot_provider.capture(
                    request.path,
                    authorized=True,
                    timeout_seconds=self.timeout_seconds,
                )
                rebuilt = await asyncio.to_thread(self.rebuilder.rebuild, snapshot)
                destination = self._job_dir(request.task_id) / "dynamic" / f"{Path(request.path).stem}.restored.exe"
                await asyncio.to_thread(self._atomic_write, destination, rebuilt.data)
                selected_path = str(destination)
                output_paths.append(selected_path)
                records.append({
                    "stage": "dynamic_snapshot",
                    "status": "completed",
                    "provider": type(self.snapshot_provider).__name__,
                    "section_count": rebuilt.section_count,
                    "import_count": rebuilt.import_count,
                    "entry_point_rva": rebuilt.entry_point_rva,
                    "capture_evidence": snapshot.capture_evidence,
                })
        elif isinstance(selected, dict):
            records.append({
                "stage": "strategy_selection",
                "status": "dynamic_authorization_required",
                "reason": "the selected protector is not supported by a deterministic static adapter",
            })

        validation = await self._validate(request, selected_path)
        success = selected_path != request.path and validation["parseable"]
        return {
            "schema_version": 1,
            "engine": "program-restoration-engine",
            "input_path": request.path,
            "output_path": selected_path if success else None,
            "output_paths": output_paths,
            "success": success,
            "status": "restored" if success else "analysis_only",
            "protection": assessment,
            "strategy": strategy,
            "records": records,
            "validation": validation,
            "metrics": {
                "elapsed_ms": round((monotonic() - started) * 1000, 2),
                "artifact_count": len(output_paths),
                "parseable": validation["parseable"],
            },
            "safety": {
                "authorization_confirmed": True,
                "dynamic_authorized": dynamic_authorized,
                "host_process_execution": False,
                "dynamic_provider_configured": self.snapshot_provider is not None or self.dex_provider is not None,
            },
        }

    async def _validate(self, request: BinaryAnalysisRequest, path: str) -> dict[str, Any]:
        try:
            result = await self.analyzer.analyze(request.model_copy(update={"path": path}))
        except Exception as exc:
            return {"parseable": False, "error_type": type(exc).__name__, "functions": 0, "imports": 0}
        details = result.metadata.get("format_details", {})
        return {
            "parseable": True,
            "file_format": result.file_format,
            "architecture": result.architecture,
            "imports": len(result.imports),
            "functions": len(result.functions),
            "dex_checksum_valid": details.get("checksum_valid") if isinstance(details, dict) else None,
            "dex_signature_valid": details.get("signature_valid") if isinstance(details, dict) else None,
            "sha256": result.metadata.get("sha256"),
        }

    async def _restore_dex(
        self,
        request: BinaryAnalysisRequest,
        *,
        dynamic_authorized: bool,
        emulator_serial: str | None,
    ) -> dict[str, Any]:
        if not dynamic_authorized:
            return {"stage": "frida_dex_capture", "status": "dynamic_authorization_required", "output_paths": []}
        if not emulator_serial or not emulator_serial.startswith("emulator-"):
            return {"stage": "frida_dex_capture", "status": "blocked", "reason": "a local emulator-* serial is required", "output_paths": []}
        if self.dex_provider is None:
            return {"stage": "frida_dex_capture", "status": "not_configured", "output_paths": []}
        payloads = await self.dex_provider.capture_dex(
            request.path,
            authorized=True,
            emulator_serial=emulator_serial,
            timeout_seconds=self.timeout_seconds,
        )
        outputs: list[str] = []
        for index, data in enumerate(payloads[:64]):
            if not is_dex(data):
                continue
            data = repair_dex_header(data)
            destination = self._job_dir(request.task_id) / "dex" / f"classes-restored-{index + 1}.dex"
            await asyncio.to_thread(self._atomic_write, destination, data)
            outputs.append(str(destination))
        return {"stage": "frida_dex_capture", "status": "completed" if outputs else "no_valid_dex", "output_paths": outputs}

    def _job_dir(self, task_id: str) -> Path:
        safe = "".join(character for character in task_id if character.isalnum() or character in "-_")[:128]
        if not safe:
            raise ValueError("task_id cannot form a safe artifact directory")
        root = self.output_root.resolve()
        destination = (root / safe).resolve()
        if not destination.is_relative_to(root):
            raise ValueError("restoration output escaped its configured root")
        return destination

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(data)
        os.replace(temporary, path)
