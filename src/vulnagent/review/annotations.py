"""Small persistent store for manual review and correction notes."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class HumanReviewUpdate(BaseModel):
    """Editable fields accepted from the frontend."""

    decision: Literal["accepted", "rejected", "needs_followup"]
    note: str = Field(default="", max_length=4000)
    reviewer: str = Field(default="course-reviewer", min_length=1, max_length=120)


class HumanReviewAnnotation(HumanReviewUpdate):
    """Persisted annotation that never overwrites VerificationResult."""

    annotation_id: str
    task_id: str
    vulnerability_id: str
    updated_at: str = Field(default_factory=_now_iso)


class ReviewAnnotationStore:
    """JSON-backed annotation store with bounded, atomic replacement."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._lock = RLock()

    def list_for_task(self, task_id: str) -> list[HumanReviewAnnotation]:
        """Return annotations for one task in stable finding order."""

        with self._lock:
            values = self._read().values()
            return sorted(
                [item.model_copy(deep=True) for item in values if item.task_id == task_id],
                key=lambda item: item.vulnerability_id,
            )

    def get(self, task_id: str, vulnerability_id: str) -> HumanReviewAnnotation | None:
        """Return one annotation if it exists."""

        with self._lock:
            item = self._read().get(self._key(task_id, vulnerability_id))
            return item.model_copy(deep=True) if item is not None else None

    def put(
        self,
        task_id: str,
        vulnerability_id: str,
        update: HumanReviewUpdate,
    ) -> HumanReviewAnnotation:
        """Create or replace the note for one finding."""

        with self._lock:
            values = self._read()
            key = self._key(task_id, vulnerability_id)
            previous = values.get(key)
            item = HumanReviewAnnotation(
                annotation_id=(previous.annotation_id if previous else f"annotation-{uuid4()}"),
                task_id=task_id,
                vulnerability_id=vulnerability_id,
                decision=update.decision,
                note=update.note,
                reviewer=update.reviewer,
                updated_at=_now_iso(),
            )
            values[key] = item
            self._write(values)
            return item.model_copy(deep=True)

    @staticmethod
    def _key(task_id: str, vulnerability_id: str) -> str:
        return f"{task_id}\n{vulnerability_id}"

    def _read(self) -> dict[str, HumanReviewAnnotation]:
        if not self.path.is_file():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, list):
            return {}
        items: dict[str, HumanReviewAnnotation] = {}
        for value in raw:
            try:
                item = HumanReviewAnnotation.model_validate(value)
            except (TypeError, ValueError):
                continue
            items[self._key(item.task_id, item.vulnerability_id)] = item
        return items

    def _write(self, values: dict[str, HumanReviewAnnotation]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        payload = [item.model_dump(mode="json") for _, item in sorted(values.items())]
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
