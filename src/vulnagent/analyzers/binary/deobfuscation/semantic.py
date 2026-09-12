"""Bounded LLM readability annotations for deterministic recovery output."""

from __future__ import annotations

import json
from typing import Any

from vulnagent.llm.base import BaseLLM


class SemanticRecoveryEnhancer:
    """Ask an injected model for public annotations, never executable rewrites."""

    def __init__(self, llm: BaseLLM | None, *, max_functions: int = 8) -> None:
        self.llm = llm
        self.max_functions = max_functions

    async def enhance(self, recovery: dict[str, Any]) -> dict[str, Any]:
        if self.llm is None:
            return {"used": False, "status": "not_configured", "annotations": []}
        functions = recovery.get("instruction_recovery", {}).get("functions", [])
        excerpts = [
            {"address": item.get("address"), "code": str(item.get("after", ""))[:3000]}
            for item in functions[: self.max_functions]
            if isinstance(item, dict)
        ]
        prompt = json.dumps({
            "task": "annotate restored pseudocode for defensive vulnerability auditing",
            "detected_obfuscation": recovery.get("detected_types", []),
            "functions": excerpts,
            "output_schema": {
                "business_summary": "short string",
                "annotations": [{"address": "string", "purpose": "string", "audit_focus": ["short labels"]}],
                "readability_score": "integer 0..100",
            },
            "constraints": [
                "JSON only",
                "do not invent missing behavior",
                "do not provide exploit code",
                "explain uncertainty in purpose",
                "no chain-of-thought",
            ],
        }, ensure_ascii=False, separators=(",", ":"))
        try:
            raw = await self.llm.generate(
                prompt,
                system_prompt="You are a defensive binary-audit annotation assistant. Return compact JSON only.",
                max_tokens=700,
                temperature=0.0,
                response_format={"type": "json_object"},
                thinking={"type": "disabled"},
            )
            parsed = json.loads(raw)
            annotations = parsed.get("annotations", []) if isinstance(parsed, dict) else []
            return {
                "used": True,
                "status": "accepted",
                "provider": type(self.llm).__name__,
                "business_summary": str(parsed.get("business_summary", ""))[:1000],
                "readability_score": max(0, min(100, int(parsed.get("readability_score", 0)))),
                "annotations": [dict(item) for item in annotations[:32] if isinstance(item, dict)],
            }
        except Exception as exc:
            return {"used": True, "status": "fallback", "error_type": type(exc).__name__, "annotations": []}
