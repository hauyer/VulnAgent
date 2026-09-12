"""Persistent custom acceptance-batch associations and read-only projections.

The fixed course benchmark remains owned by :mod:`vulnagent.acceptance.calculator`.
This module records a separate, user-selected batch that links local models and
already-authorized laboratory tasks to their target files and generated reports.
It deliberately reports execution completeness only: arbitrary uploaded files
do not acquire classification metrics without an explicit ground-truth set.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Iterable
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from vulnagent.contracts import Task, TaskStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CustomBatchState(str, Enum):
    """Lifecycle of one configured custom acceptance batch."""

    CONFIGURED = "configured"
    PARTIAL = "partial"
    COMPLETED = "completed"


class CustomAcceptanceBatchCreate(BaseModel):
    """Selections accepted when creating one custom acceptance batch."""

    name: str = Field(min_length=1, max_length=160)
    model_names: list[str] = Field(min_length=1, max_length=10)
    model_task_ids: list[str] = Field(default_factory=list, max_length=20)
    packed_task_ids: list[str] = Field(min_length=2, max_length=50)
    obfuscated_task_ids: list[str] = Field(min_length=2, max_length=50)

    @field_validator(
        "model_names",
        "model_task_ids",
        "packed_task_ids",
        "obfuscated_task_ids",
    )
    @classmethod
    def _strip_and_deduplicate(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values if value and value.strip()]
        return list(dict.fromkeys(cleaned))

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _validate_distinct_groups(self) -> "CustomAcceptanceBatchCreate":
        if not self.model_names:
            raise ValueError("At least one distinct model is required")
        overlap = set(self.packed_task_ids).intersection(self.obfuscated_task_ids)
        if overlap:
            raise ValueError("A task cannot belong to both packed and obfuscated groups")
        if len(self.packed_task_ids) < 2:
            raise ValueError("Packed group requires at least two distinct tasks")
        if len(self.obfuscated_task_ids) < 2:
            raise ValueError("Obfuscated group requires at least two distinct tasks")
        return self


class CustomAcceptanceBatchRecord(CustomAcceptanceBatchCreate):
    """Durable association record; live task/report facts are projected later."""

    batch_id: str
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)


class CustomAcceptanceTaskLink(BaseModel):
    """One explicit task → target/model → report relationship."""

    task_id: str
    group_id: str
    target_id: str
    target_path: str
    file_name: str
    target_type: str
    file_format: str | None = None
    sha256: str | None = None
    model_name: str | None = None
    protection_category: str | None = None
    declared_protection: str | None = None
    observed_protection_methods: list[str] = Field(default_factory=list)
    task_status: str
    finding_count: int = 0
    evidence_count: int = 0
    verification_count: int = 0
    report_available: bool = False
    report_links: dict[str, str] = Field(default_factory=dict)
    missing: bool = False


class CustomAcceptanceGroupProgress(BaseModel):
    """Execution-only progress for one custom A/B/C group."""

    group_id: str
    title: str
    required_count: int
    selected_count: int
    completed_count: int
    execution_complete: bool
    metric_status: str = "not_evaluated"
    summary: str


class CustomAcceptanceBatch(BaseModel):
    """Frontend/report projection of one persistent custom batch."""

    batch_id: str
    name: str
    state: CustomBatchState
    created_at: str
    updated_at: str
    model_names: list[str]
    model_task_ids: list[str]
    packed_task_ids: list[str]
    obfuscated_task_ids: list[str]
    completed_groups: int
    total_groups: int = 3
    groups: list[CustomAcceptanceGroupProgress]
    task_links: list[CustomAcceptanceTaskLink]
    metric_note: str = (
        "自定义上传样本没有 Ground Truth，只统计执行完成度；"
        "Precision/Recall/F1 仍以固定 Benchmark 规范产物为准。"
    )


class AcceptanceBatchStore:
    """JSON-backed store for batch association records with atomic replacement."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._lock = RLock()

    def list(self) -> list[CustomAcceptanceBatchRecord]:
        """Return newest records first."""

        with self._lock:
            return sorted(
                [item.model_copy(deep=True) for item in self._read().values()],
                key=lambda item: (item.created_at, item.batch_id),
                reverse=True,
            )

    def get(self, batch_id: str) -> CustomAcceptanceBatchRecord | None:
        """Return one record by id."""

        with self._lock:
            item = self._read().get(batch_id)
            return item.model_copy(deep=True) if item is not None else None

    def create(self, payload: CustomAcceptanceBatchCreate) -> CustomAcceptanceBatchRecord:
        """Persist one new association record."""

        with self._lock:
            records = self._read()
            now = _now_iso()
            item = CustomAcceptanceBatchRecord(
                batch_id=f"acceptance-{uuid4()}",
                created_at=now,
                updated_at=now,
                **payload.model_dump(),
            )
            records[item.batch_id] = item
            self._write(records)
            return item.model_copy(deep=True)

    def find_for_task(self, task_id: str) -> list[CustomAcceptanceBatchRecord]:
        """Return every batch that explicitly contains ``task_id``."""

        return [
            item
            for item in self.list()
            if task_id
            in {
                *item.model_task_ids,
                *item.packed_task_ids,
                *item.obfuscated_task_ids,
            }
        ]

    def _read(self) -> dict[str, CustomAcceptanceBatchRecord]:
        if not self.path.is_file():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, list):
            return {}
        result: dict[str, CustomAcceptanceBatchRecord] = {}
        for value in raw:
            try:
                item = CustomAcceptanceBatchRecord.model_validate(value)
            except (TypeError, ValueError):
                continue
            result[item.batch_id] = item
        return result

    def _write(self, values: dict[str, CustomAcceptanceBatchRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        payload = [item.model_dump(mode="json") for _, item in sorted(values.items())]
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()


def task_category(task: Task) -> str | None:
    """Read the canonical test-lab category from task/target metadata."""

    value = task.target.metadata.get("test_lab_category") or task.metadata.get(
        "test_lab_category"
    )
    return str(value) if value else None


def task_model_name(task: Task) -> str | None:
    """Read a model name from an archived local-model task."""

    value = task.target.metadata.get("model_name") or task.metadata.get("model_name")
    return str(value) if value else None


def _observed_protection_methods(context: Any) -> list[str]:
    """Project stable protection-signal codes from existing Evidence records."""

    if context is None:
        return []
    methods: list[str] = []
    for evidence in context.evidence:
        if evidence.source == "binary_reverse":
            raw = evidence.data.get("observed_protection_methods")
            if isinstance(raw, list):
                methods.extend(str(item) for item in raw if item)
            packing = evidence.data.get("packing_signals")
            if isinstance(packing, dict) and isinstance(packing.get("signals"), list):
                methods.extend(str(item) for item in packing["signals"] if item)
        if evidence.source == "binary_obfuscation":
            raw = evidence.data.get("observed_methods")
            if isinstance(raw, list):
                methods.extend(str(item) for item in raw if item)
            signals = evidence.data.get("signals")
            if isinstance(signals, list):
                methods.extend(
                    str(item.get("name") or item.get("kind") or item.get("type"))
                    for item in signals
                    if isinstance(item, dict)
                    and (item.get("name") or item.get("kind") or item.get("type"))
                )
        if evidence.source == "binary_logic":
            deobfuscation = evidence.data.get("deobfuscation")
            items = deobfuscation.get("items") if isinstance(deobfuscation, dict) else None
            if isinstance(items, list):
                methods.extend(
                    f"{item.get('encoding')}_decode"
                    for item in items
                    if isinstance(item, dict) and item.get("encoding")
                )
    return list(dict.fromkeys(methods))


def validate_batch_tasks(
    payload: CustomAcceptanceBatchCreate,
    tasks: Iterable[Task],
) -> CustomAcceptanceBatchCreate:
    """Validate group ownership and auto-link latest model tasks where possible."""

    task_list = list(tasks)
    by_id = {task.task_id: task for task in task_list}
    requested_ids = {
        *payload.model_task_ids,
        *payload.packed_task_ids,
        *payload.obfuscated_task_ids,
    }
    missing = sorted(requested_ids.difference(by_id))
    if missing:
        raise ValueError(f"Unknown task id(s): {', '.join(missing)}")

    wrong_packed = [
        task_id
        for task_id in payload.packed_task_ids
        if (
            task_category(by_id[task_id]) != "packed_binary"
            or by_id[task_id].target.target_type.value != "binary"
        )
    ]
    if wrong_packed:
        raise ValueError(
            "Packed group contains non-packed task(s): " + ", ".join(wrong_packed)
        )
    wrong_obfuscated = [
        task_id
        for task_id in payload.obfuscated_task_ids
        if (
            task_category(by_id[task_id]) != "obfuscated_binary"
            or by_id[task_id].target.target_type.value != "binary"
        )
    ]
    if wrong_obfuscated:
        raise ValueError(
            "Obfuscated group contains non-obfuscated task(s): "
            + ", ".join(wrong_obfuscated)
        )

    selected_models = {name.casefold() for name in payload.model_names}
    explicit_model_tasks = list(payload.model_task_ids)
    for task_id in explicit_model_tasks:
        model_name = task_model_name(by_id[task_id])
        if model_name is None or model_name.casefold() not in selected_models:
            raise ValueError(
                f"Model task {task_id} does not belong to a selected model"
            )

    # Auto-link the newest archived task for any selected model not explicitly linked.
    linked_models = {
        task_model_name(by_id[task_id]).casefold()
        for task_id in explicit_model_tasks
        if task_model_name(by_id[task_id])
    }
    for model_name in payload.model_names:
        if model_name.casefold() in linked_models:
            continue
        candidates = [
            task
            for task in task_list
            if task_model_name(task)
            and task_model_name(task).casefold() == model_name.casefold()
            and task.metadata.get("source") == "llm_vulnerability_scanner"
        ]
        if candidates:
            newest = max(candidates, key=lambda item: item.updated_at)
            explicit_model_tasks.append(newest.task_id)

    return payload.model_copy(update={"model_task_ids": explicit_model_tasks})


def attach_batch_metadata(task_manager: Any, record: CustomAcceptanceBatchRecord) -> None:
    """Add the batch id as a durable back-reference on every associated task."""

    for task_id in dict.fromkeys(
        [*record.model_task_ids, *record.packed_task_ids, *record.obfuscated_task_ids]
    ):
        task = task_manager.get_task(task_id)
        if task is None:
            continue
        batch_ids = list(task.metadata.get("acceptance_batch_ids") or [])
        if record.batch_id not in batch_ids:
            batch_ids.append(record.batch_id)
            task_manager.update_task(task_id, metadata={"acceptance_batch_ids": batch_ids})


def project_batch(record: CustomAcceptanceBatchRecord, request: Any) -> CustomAcceptanceBatch:
    """Resolve current task, file, model and report facts for one batch record."""

    task_manager = request.app.state.task_manager
    orchestrator = request.app.state.orchestrator
    by_id = {task.task_id: task for task in task_manager.list_tasks()}

    def link(task_id: str, group_id: str) -> CustomAcceptanceTaskLink:
        task = by_id.get(task_id)
        if task is None:
            return CustomAcceptanceTaskLink(
                task_id=task_id,
                group_id=group_id,
                target_id="missing",
                target_path="",
                file_name="missing task",
                target_type="unknown",
                task_status="missing",
                missing=True,
            )
        context = orchestrator.get_context(task_id)
        report_available = bool(context and context.reports)
        return CustomAcceptanceTaskLink(
            task_id=task.task_id,
            group_id=group_id,
            target_id=task.target.target_id,
            target_path=task.target.path,
            file_name=Path(task.target.path).name or task.target.path,
            target_type=task.target.target_type.value,
            file_format=task.target.file_format,
            sha256=(
                task.target.metadata.get("expected_sha256")
                or task.target.metadata.get("sha256")
            ),
            model_name=task_model_name(task),
            protection_category=task_category(task),
            declared_protection=(
                str(task.target.metadata.get("protection"))
                if task.target.metadata.get("protection")
                else None
            ),
            observed_protection_methods=_observed_protection_methods(context),
            task_status=task.status.value,
            finding_count=len(context.findings) if context else 0,
            evidence_count=len(context.evidence) if context else 0,
            verification_count=len(context.verifications) if context else 0,
            report_available=report_available,
            report_links=(
                {
                    "json": f"/api/tasks/{task_id}/report",
                    "html": f"/api/tasks/{task_id}/report.html",
                    "pdf": f"/api/tasks/{task_id}/report.pdf",
                }
                if report_available
                else {}
            ),
        )

    links = [
        *[link(task_id, "a") for task_id in record.model_task_ids],
        *[link(task_id, "b") for task_id in record.packed_task_ids],
        *[link(task_id, "c") for task_id in record.obfuscated_task_ids],
    ]

    def task_done(item: CustomAcceptanceTaskLink) -> bool:
        return item.task_status == TaskStatus.COMPLETED.value and item.report_available

    completed_models = {
        item.model_name.casefold()
        for item in links
        if item.group_id == "a" and item.model_name and task_done(item)
    }
    model_count = sum(
        1 for name in record.model_names if name.casefold() in completed_models
    )
    binary_links = {
        group_id: [item for item in links if item.group_id == group_id]
        for group_id in ("b", "c")
    }
    groups = [
        CustomAcceptanceGroupProgress(
            group_id="a",
            title="开源大模型漏洞扫描",
            required_count=len(record.model_names),
            selected_count=len(record.model_names),
            completed_count=model_count,
            execution_complete=model_count == len(record.model_names),
            summary=(
                f"{model_count}/{len(record.model_names)} 个所选模型已有完成任务与报告。"
            ),
        ),
        *[
            CustomAcceptanceGroupProgress(
                group_id=group_id,
                title=("加壳软件漏洞测试" if group_id == "b" else "混淆软件漏洞测试"),
                required_count=2,
                selected_count=len(binary_links[group_id]),
                completed_count=sum(task_done(item) for item in binary_links[group_id]),
                execution_complete=(
                    len(binary_links[group_id]) >= 2
                    and all(task_done(item) for item in binary_links[group_id])
                ),
                summary=(
                    f"{sum(task_done(item) for item in binary_links[group_id])}/"
                    f"{len(binary_links[group_id])} 个关联任务已完成并生成报告。"
                ),
            )
            for group_id in ("b", "c")
        ],
    ]
    completed_groups = sum(group.execution_complete for group in groups)
    state = (
        CustomBatchState.COMPLETED
        if completed_groups == 3
        else CustomBatchState.PARTIAL
        if completed_groups
        else CustomBatchState.CONFIGURED
    )
    return CustomAcceptanceBatch(
        **record.model_dump(),
        state=state,
        completed_groups=completed_groups,
        groups=groups,
        task_links=links,
    )


__all__ = [
    "AcceptanceBatchStore",
    "CustomAcceptanceBatch",
    "CustomAcceptanceBatchCreate",
    "CustomAcceptanceBatchRecord",
    "attach_batch_metadata",
    "project_batch",
    "validate_batch_tasks",
]
