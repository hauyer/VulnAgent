"""Small SQLite repository adapter for tasks, evidence and final contexts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from vulnagent.contracts import AnalysisContext, Evidence, Target, Task, TaskStatus
from vulnagent.contracts.common import utc_now
from vulnagent.utils.ids import new_task_id


class SQLiteRepository:
    """Implement repository ports using JSON snapshots in a local SQLite file.

    The adapter is intentionally narrow: Core depends on repository methods,
    while SQLite details remain behind this boundary. A connection is opened
    per operation so separate application instances can observe committed data.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_task
                    ON evidence(task_id);
                CREATE TABLE IF NOT EXISTS contexts (
                    task_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _payload(value: Any) -> str:
        return value.model_dump_json()

    def create_task(
        self,
        target: Target,
        metadata: dict[str, Any] | None = None,
    ) -> Task:
        """Create and atomically persist a new task."""
        task = Task(task_id=new_task_id(), target=target, metadata=metadata or {})
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO tasks(task_id, payload, updated_at) VALUES (?, ?, ?)",
                (task.task_id, self._payload(task), task.updated_at.isoformat()),
            )
        return task.model_copy(deep=True)

    def get_task(self, task_id: str) -> Task | None:
        """Load one isolated task snapshot."""
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return None if row is None else Task.model_validate_json(row[0])

    def list_tasks(self) -> list[Task]:
        """List tasks from newest update to oldest."""
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM tasks ORDER BY updated_at DESC, task_id"
            ).fetchall()
        return [Task.model_validate_json(row[0]) for row in rows]

    def update_task(
        self,
        task_id: str,
        *,
        status: TaskStatus | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Task:
        """Update a task snapshot under one SQLite transaction."""
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown task: {task_id}")
            updated = Task.model_validate_json(row[0])
            if status is not None:
                updated.status = status
            if error is not None:
                updated.error = error
            elif status is not None and status is not TaskStatus.FAILED:
                updated.error = None
            if metadata is not None:
                updated.metadata.update(metadata)
            updated.updated_at = utc_now()
            connection.execute(
                "UPDATE tasks SET payload = ?, updated_at = ? WHERE task_id = ?",
                (self._payload(updated), updated.updated_at.isoformat(), task_id),
            )
        return updated.model_copy(deep=True)

    def add(self, evidence: Evidence) -> Evidence:
        """Backward-compatible alias for ``save``."""
        return self.save(evidence)

    def save(self, evidence: Evidence) -> Evidence:
        """Persist evidence with semantic de-duplication across restarts."""
        fingerprint = self._evidence_fingerprint(evidence)
        with self._lock, self._connect() as connection:
            duplicate = connection.execute(
                "SELECT payload FROM evidence WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if duplicate is not None:
                return Evidence.model_validate_json(duplicate[0])
            connection.execute(
                """
                INSERT INTO evidence(
                    evidence_id, task_id, fingerprint, payload, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    task_id = excluded.task_id,
                    fingerprint = excluded.fingerprint,
                    payload = excluded.payload,
                    created_at = excluded.created_at
                """,
                (
                    evidence.evidence_id,
                    evidence.task_id,
                    fingerprint,
                    self._payload(evidence),
                    evidence.created_at.isoformat(),
                ),
            )
        return evidence.model_copy(deep=True)

    @staticmethod
    def _evidence_fingerprint(evidence: Evidence) -> str:
        payload = evidence.model_dump(
            mode="json",
            exclude={"evidence_id", "created_at"},
        )
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def get(self, evidence_id: str) -> Evidence | None:
        """Load one evidence snapshot."""
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM evidence WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else Evidence.model_validate_json(row[0])

    def list_by_task(self, task_id: str) -> list[Evidence]:
        """List evidence for one task in creation order."""
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload FROM evidence
                WHERE task_id = ? ORDER BY created_at, evidence_id
                """,
                (task_id,),
            ).fetchall()
        return [Evidence.model_validate_json(row[0]) for row in rows]

    def list_by_finding(self, finding_id: str) -> list[Evidence]:
        """Filter structured finding associations without SQL JSON extensions."""
        return [
            item
            for task in self.list_tasks()
            for item in self.list_by_task(task.task_id)
            if item.data.get("finding_id") == finding_id
            or finding_id in item.data.get("finding_ids", [])
        ]

    def save_context(self, context: AnalysisContext) -> AnalysisContext:
        """Persist the complete API-facing analysis aggregate."""
        snapshot = context.model_copy(deep=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO contexts(task_id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (
                    snapshot.task.task_id,
                    self._payload(snapshot),
                    snapshot.task.updated_at.isoformat(),
                ),
            )
        return snapshot.model_copy(deep=True)

    def get_context(self, task_id: str) -> AnalysisContext | None:
        """Load a final context for API queries after process restart."""
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM contexts WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return None if row is None else AnalysisContext.model_validate_json(row[0])


__all__ = ["SQLiteRepository"]
