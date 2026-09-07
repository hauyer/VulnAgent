"""Structured report generator."""

from typing import Any

from vulnagent.core.models import AnalysisContext


def generate_report(context: AnalysisContext) -> dict[str, Any]:
    return {"task": context.task.model_dump(mode="json"), "findings": [item.model_dump(mode="json") for item in context.findings], "evidence": [item.model_dump(mode="json") for item in context.evidence], "mock": True}

