"""Centralized identifier generation."""

from uuid import uuid4


def _new(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def new_task_id() -> str:
    return _new("task")


def new_target_id() -> str:
    return _new("target")


def new_message_id() -> str:
    return _new("message")


def new_evidence_id() -> str:
    return _new("evidence")


def new_vulnerability_id() -> str:
    return _new("vulnerability")

