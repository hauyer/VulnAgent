"""Atomic JSON persistence for bounded binary-analysis artifacts.

The index lock is intentionally process-local.  Multiple store instances in one
Python process cannot lose each other's index entry; coordinating independent
processes requires a caller-provided single-writer policy or a future OS-level
lock implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping

from vulnagent.contracts import BinaryAnalysisResult


class BinaryArtifactStore:
    """Persist validated JSON snapshots under a caller-controlled directory."""

    _locks_guard = threading.Lock()
    _locks: dict[str, threading.RLock] = {}

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self._lock = self._lock_for(self.root)

    def save_result(
        self, result: BinaryAnalysisResult, *, extra: Mapping[str, Any] | None = None
    ) -> Path:
        """Atomically save a result and update the process-local protected index."""
        _validate_json_value(result.model_dump(mode="json"))
        safe_task = _safe_component(result.task_id)
        safe_target = _safe_component(result.target_id)
        suffix = hashlib.sha256(f"{result.task_id}\0{result.target_id}".encode("utf-8")).hexdigest()[:16]
        artifact_id = f"{safe_task[:80]}-{safe_target[:80]}-{suffix}"
        record: dict[str, Any] = {
            "artifact_version": 2,
            "kind": "binary_analysis",
            "task_id": result.task_id,
            "target_id": result.target_id,
            "result": result.model_dump(mode="json"),
            "extra": dict(extra or {}),
        }
        _validate_json_value(record)
        target = self.root / f"{artifact_id}.json"
        with self._lock:
            self._atomic_json(target, record)
            index = self._load_index()
            records = [item for item in index["artifacts"] if item["artifact_id"] != artifact_id]
            records.append({"artifact_id": artifact_id, "path": target.name, "task_id": result.task_id, "target_id": result.target_id})
            index["artifacts"] = sorted(records, key=lambda item: item["artifact_id"])
            self._atomic_json(self.root / "index.json", index)
        return target

    def list_by_task(self, task_id: str) -> list[dict[str, str]]:
        """Return validated index entries for a task without arbitrary paths."""
        with self._lock:
            return [item.copy() for item in self._load_index()["artifacts"] if item["task_id"] == task_id]

    def load(self, artifact_id: str) -> dict[str, Any] | None:
        """Load exactly one artifact that is referenced by the validated index."""
        with self._lock:
            entry = next((item for item in self._load_index()["artifacts"] if item["artifact_id"] == artifact_id), None)
            if entry is None:
                return None
            path = self.root / entry["path"]
            if not path.is_file():
                raise ValueError("indexed artifact is missing")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid artifact: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("invalid artifact shape")
            _validate_json_value(payload)
            return payload

    @classmethod
    def _lock_for(cls, root: Path) -> threading.RLock:
        key = str(root.resolve())
        with cls._locks_guard:
            return cls._locks.setdefault(key, threading.RLock())

    def _load_index(self) -> dict[str, list[dict[str, str]]]:
        path = self.root / "index.json"
        if not path.is_file():
            return {"artifact_version": 2, "artifacts": []}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid artifact index: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("artifact_version") not in {1, 2} or not isinstance(payload.get("artifacts"), list):
            raise ValueError("invalid artifact index shape")
        artifacts: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in payload["artifacts"]:
            if not isinstance(item, dict) or set(item) != {"artifact_id", "path", "task_id", "target_id"}:
                raise ValueError("invalid artifact index entry")
            if not all(isinstance(item[key], str) for key in item):
                raise ValueError("invalid artifact index entry types")
            artifact_id = item["artifact_id"]
            if artifact_id in seen or _safe_component(artifact_id) != artifact_id or item["path"] != f"{artifact_id}.json":
                raise ValueError("invalid artifact index entry values")
            seen.add(artifact_id)
            artifacts.append(dict(item))
        return {"artifact_version": 2, "artifacts": artifacts}

    def _atomic_json(self, path: Path, data: Mapping[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        _validate_json_value(data)
        try:
            encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"artifact is not JSON serializable: {exc}") from exc
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


def _safe_component(value: str) -> str:
    clean = "".join(char if char.isalnum() or char in "-_" else "_" for char in value)
    if not clean or clean in {".", ".."}:
        raise ValueError("artifact identifier must contain safe characters")
    return clean[:200]


def _validate_json_value(value: Any) -> None:
    """Reject non-finite numbers and non-JSON-compatible nested values early."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("artifact is not JSON serializable: non-finite float")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("artifact is not JSON serializable: object keys must be strings")
        for item in value.values():
            _validate_json_value(item)
        return
    raise ValueError(f"artifact is not JSON serializable: unsupported value {type(value).__name__}")
