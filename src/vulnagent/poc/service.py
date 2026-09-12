"""Generate bounded PoC evidence-replay code for confirmed local findings.

This module intentionally does not generate weaponized exploits.  A generated
script can only read one already-audited local artifact, verify its SHA-256 and
replay a source-line or binary-format evidence check.  It has no target process
execution, networking, command execution, privilege, persistence or bypass
capability.  This is the controlled PoC boundary permitted by ``AGENTS.md``.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from vulnagent.contracts import TaskStatus


_MAX_TARGET_BYTES = 64 * 1024 * 1024


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PocGenerationError(ValueError):
    """Raised when the requested finding is outside the controlled boundary."""


class ControlledPocGenerationRequest(BaseModel):
    """Explicit request for a confirmed-finding evidence replay."""

    vulnerability_id: str = Field(min_length=1, max_length=200)
    acknowledge_controlled_scope: bool = False


class ControlledPocBundle(BaseModel):
    """Persisted, downloadable controlled-PoC bundle projection."""

    bundle_id: str
    task_id: str
    vulnerability_id: str
    title: str
    vulnerability_type: str
    cwe_id: str | None = None
    target_type: str
    target_path: str
    target_sha256: str
    verification_status: str
    verification_confidence: float
    verification_rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    code_kind: str = "evidence_replay"
    language: str = "python"
    filename: str = "poc_replay.py"
    code: str
    artifact_path: str
    artifact_uri: str
    created_at: str = Field(default_factory=_now_iso)
    safety_profile: dict[str, bool] = Field(
        default_factory=lambda: {
            "local_only": True,
            "target_execution": False,
            "network_access": False,
            "command_execution": False,
            "privilege_escalation": False,
            "persistence": False,
            "evasion": False,
        }
    )
    checks: list[str] = Field(default_factory=list)


class ControlledPocStore:
    """Atomic JSON index plus immutable generated-code artifacts."""

    def __init__(self, index_path: Path, artifacts_root: Path) -> None:
        self.index_path = index_path.resolve()
        self.artifacts_root = artifacts_root.resolve()
        self._lock = RLock()

    def list_for_task(self, task_id: str) -> list[ControlledPocBundle]:
        """Return newest bundles for a task."""

        with self._lock:
            return sorted(
                [
                    item.model_copy(deep=True)
                    for item in self._read().values()
                    if item.task_id == task_id
                ],
                key=lambda item: (item.created_at, item.bundle_id),
                reverse=True,
            )

    def get(self, bundle_id: str) -> ControlledPocBundle | None:
        """Return one bundle by id."""

        with self._lock:
            item = self._read().get(bundle_id)
            return item.model_copy(deep=True) if item else None

    def save(self, bundle: ControlledPocBundle) -> ControlledPocBundle:
        """Write code and index atomically enough for local single-process use."""

        with self._lock:
            destination = Path(bundle.artifact_path).resolve()
            try:
                destination.relative_to(self.artifacts_root)
            except ValueError as exc:
                raise PocGenerationError("PoC artifact path escaped the controlled root") from exc
            destination.parent.mkdir(parents=True, exist_ok=True)
            code_temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
            code_temporary.write_text(bundle.code, encoding="utf-8")
            os.replace(code_temporary, destination)

            values = self._read()
            values[bundle.bundle_id] = bundle.model_copy(deep=True)
            self._write(values)
            return bundle.model_copy(deep=True)

    def _read(self) -> dict[str, ControlledPocBundle]:
        if not self.index_path.is_file():
            return {}
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, list):
            return {}
        result: dict[str, ControlledPocBundle] = {}
        for value in raw:
            try:
                item = ControlledPocBundle.model_validate(value)
            except (TypeError, ValueError):
                continue
            result[item.bundle_id] = item
        return result

    def _write(self, values: dict[str, ControlledPocBundle]) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.index_path.with_name(
            f".{self.index_path.name}.{uuid4().hex}.tmp"
        )
        payload = [item.model_dump(mode="json") for _, item in sorted(values.items())]
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.replace(temporary, self.index_path)
        finally:
            temporary.unlink(missing_ok=True)


class ControlledPocService:
    """Create read-only evidence replay scripts after independent verification."""

    def __init__(
        self,
        *,
        repository_root: Path,
        task_manager: Any,
        orchestrator: Any,
        store: ControlledPocStore,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.task_manager = task_manager
        self.orchestrator = orchestrator
        self.store = store

    def list_for_task(self, task_id: str) -> list[ControlledPocBundle]:
        """List bundles after validating that the task exists."""

        if self.task_manager.get_task(task_id) is None:
            raise KeyError(task_id)
        return self.store.list_for_task(task_id)

    def get(self, task_id: str, bundle_id: str) -> ControlledPocBundle:
        """Return a bundle only under its owning task."""

        if self.task_manager.get_task(task_id) is None:
            raise KeyError(task_id)
        bundle = self.store.get(bundle_id)
        if bundle is None or bundle.task_id != task_id:
            raise KeyError(bundle_id)
        return bundle

    def generate(
        self,
        task_id: str,
        payload: ControlledPocGenerationRequest,
    ) -> ControlledPocBundle:
        """Generate a safe replay script for one independently confirmed finding."""

        if not payload.acknowledge_controlled_scope:
            raise PocGenerationError("Controlled PoC scope acknowledgement is required")
        task = self.task_manager.get_task(task_id)
        if task is None:
            raise KeyError(task_id)
        if task.status is not TaskStatus.COMPLETED:
            raise PocGenerationError("Task must be completed before PoC generation")
        context = self.orchestrator.get_context(task_id)
        if context is None:
            raise PocGenerationError("Completed task context is unavailable")
        finding = next(
            (
                item
                for item in context.findings
                if item.vulnerability_id == payload.vulnerability_id
            ),
            None,
        )
        if finding is None:
            raise PocGenerationError("Vulnerability does not belong to this task")
        verification = next(
            (
                item
                for item in context.verifications
                if item.vulnerability_id == finding.vulnerability_id
            ),
            None,
        )
        if (
            verification is None
            or verification.status.value != "confirmed"
            or finding.status.value != "confirmed"
        ):
            raise PocGenerationError(
                "Only independently confirmed vulnerabilities can produce a controlled PoC"
            )
        if task.target.target_type.value not in {"source", "binary", "project"}:
            raise PocGenerationError("This target type has no safe file replay profile")
        self._validate_local_target(task.target.path)
        if task.target.target_type.value == "binary" and not bool(
            task.target.metadata.get("authorization_confirmed")
        ):
            raise PocGenerationError(
                "Binary PoC generation requires authorization_confirmed=true"
            )

        target = self._resolve_evidence_file(task.target.path, finding.location)
        size = target.stat().st_size
        if size > _MAX_TARGET_BYTES:
            raise PocGenerationError("Target exceeds the 64 MiB controlled PoC limit")
        target_sha256 = self._sha256(target)
        replay_manifest, checks = self._replay_manifest(
            target=target,
            target_type=task.target.target_type.value,
            target_sha256=target_sha256,
            finding=finding,
            verification=verification,
        )
        code = self._render_replay_code(replay_manifest)
        bundle_id = f"poc-{uuid4()}"
        filename = "poc_replay.py"
        artifact_path = self.store.artifacts_root / bundle_id / filename
        bundle = ControlledPocBundle(
            bundle_id=bundle_id,
            task_id=task_id,
            vulnerability_id=finding.vulnerability_id,
            title=finding.title,
            vulnerability_type=finding.vulnerability_type,
            cwe_id=finding.cwe_id,
            target_type=task.target.target_type.value,
            target_path=str(target),
            target_sha256=target_sha256,
            verification_status=verification.status.value,
            verification_confidence=verification.confidence,
            verification_rationale=verification.rationale,
            evidence_ids=list(dict.fromkeys(verification.evidence_ids)),
            code=code,
            artifact_path=str(artifact_path),
            artifact_uri=f"/api/tasks/{task_id}/poc/{bundle_id}/code",
            checks=checks,
        )
        saved = self.store.save(bundle)
        existing_ids = list(task.metadata.get("controlled_poc_bundle_ids") or [])
        if bundle_id not in existing_ids:
            existing_ids.append(bundle_id)
            self.task_manager.update_task(
                task_id,
                metadata={"controlled_poc_bundle_ids": existing_ids},
            )
        return saved

    @staticmethod
    def _validate_local_target(value: str) -> None:
        normalized = value.strip().casefold()
        if not normalized:
            raise PocGenerationError("Target path is empty")
        if normalized.startswith(("http://", "https://", "ftp://", "ssh://", "\\\\")):
            raise PocGenerationError("Remote and UNC targets are forbidden")

    def _resolve_evidence_file(self, target_value: str, location: Any) -> Path:
        raw_target = Path(target_value).expanduser()
        target = raw_target if raw_target.is_absolute() else self.repository_root / raw_target
        candidates: list[Path] = []
        if target.is_file():
            candidates.append(target)
        location_value = getattr(location, "file_path", None) if location else None
        if location_value:
            raw_location = Path(str(location_value)).expanduser()
            if raw_location.is_absolute():
                candidates.append(raw_location)
            else:
                candidates.extend(
                    [
                        self.repository_root / raw_location,
                        target / raw_location,
                        target / raw_location.name,
                    ]
                )
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved.is_file():
                return resolved
        raise PocGenerationError("The analyzed local evidence file is unavailable")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _replay_manifest(
        *,
        target: Path,
        target_type: str,
        target_sha256: str,
        finding: Any,
        verification: Any,
    ) -> tuple[dict[str, Any], list[str]]:
        manifest: dict[str, Any] = {
            "mode": "controlled_evidence_replay",
            "target": str(target),
            "target_type": target_type,
            "target_sha256": target_sha256,
            "vulnerability_id": finding.vulnerability_id,
            "vulnerability_type": finding.vulnerability_type,
            "cwe_id": finding.cwe_id,
            "verification_status": verification.status.value,
            "verification_confidence": verification.confidence,
            "evidence_ids": list(dict.fromkeys(verification.evidence_ids)),
        }
        checks = ["same local artifact SHA-256", "confirmed verification snapshot"]
        if target_type in {"source", "project"}:
            line_start = max(1, int(getattr(finding.location, "line_start", None) or 1))
            line_end = max(
                line_start,
                int(getattr(finding.location, "line_end", None) or line_start),
            )
            lines = target.read_bytes().splitlines(keepends=True)
            if line_start > len(lines):
                raise PocGenerationError("Verified source location is outside the target file")
            bounded_end = min(line_end, len(lines))
            window = b"".join(lines[line_start - 1 : bounded_end])
            manifest.update(
                {
                    "line_start": line_start,
                    "line_end": bounded_end,
                    "source_window_sha256": hashlib.sha256(window).hexdigest(),
                }
            )
            checks.append("verified source evidence window SHA-256")
        else:
            magic = target.read_bytes()[:4]
            expected_magic = "PE" if magic.startswith(b"MZ") else "ELF" if magic == b"\x7fELF" else "UNKNOWN"
            if expected_magic == "UNKNOWN":
                raise PocGenerationError("Controlled binary replay supports PE or ELF only")
            manifest["expected_file_format"] = expected_magic
            checks.append("binary PE/ELF header")
        return manifest, checks

    @staticmethod
    def _render_replay_code(manifest: dict[str, Any]) -> str:
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        return f'''#!/usr/bin/env python3
"""Read-only controlled PoC: replay verified evidence without executing the target."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MANIFEST = json.loads({manifest_json!r})
MAX_BYTES = {_MAX_TARGET_BYTES}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnAgent controlled evidence replay")
    parser.add_argument("--target", default=MANIFEST["target"])
    args = parser.parse_args()
    target = Path(args.target).expanduser().resolve()
    if not target.is_file():
        print(json.dumps({{"ok": False, "error": "local target file not found"}}, ensure_ascii=False))
        return 2
    if target.stat().st_size > MAX_BYTES:
        print(json.dumps({{"ok": False, "error": "target exceeds controlled size limit"}}, ensure_ascii=False))
        return 2

    observed_sha256 = sha256_file(target)
    checks = {{"target_sha256": observed_sha256 == MANIFEST["target_sha256"]}}
    data = target.read_bytes()
    if MANIFEST["target_type"] in ("source", "project"):
        lines = data.splitlines(keepends=True)
        start = MANIFEST["line_start"]
        end = MANIFEST["line_end"]
        window = b"".join(lines[start - 1:end])
        checks["source_window_sha256"] = hashlib.sha256(window).hexdigest() == MANIFEST["source_window_sha256"]
    else:
        expected = MANIFEST["expected_file_format"]
        observed = "PE" if data.startswith(b"MZ") else "ELF" if data.startswith(b"\\x7fELF") else "UNKNOWN"
        checks["binary_format"] = observed == expected and expected in ("PE", "ELF")

    result = {{
        "ok": all(checks.values()),
        "mode": MANIFEST["mode"],
        "vulnerability_id": MANIFEST["vulnerability_id"],
        "verification_status": MANIFEST["verification_status"],
        "evidence_ids": MANIFEST["evidence_ids"],
        "checks": checks,
        "safety": {{"target_executed": False, "network_used": False, "commands_run": False}},
    }}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


__all__ = [
    "ControlledPocBundle",
    "ControlledPocGenerationRequest",
    "ControlledPocService",
    "ControlledPocStore",
    "PocGenerationError",
]
