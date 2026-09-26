"""Defensive model-assisted review for software-code audit candidates."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from vulnagent.agents.base import BaseAgent
from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    Evidence,
    EvidenceType,
    Task,
    VulnerabilityCandidate,
)
from vulnagent.llm.base import BaseLLM
from vulnagent.utils.ids import new_evidence_id, new_message_id


_PROMPT_PATH = Path(__file__).resolve().parents[3] / "configs" / "prompts" / "code_audit_agent_zh.txt"
_REVIEW_RESULTS = frozenset({"likely_true_positive", "likely_false_positive", "uncertain"})
_TRIGGERABILITY = frozenset({"reachable", "conditional", "unreachable", "unknown"})
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_PROHIBITED_MARKERS = (
    "exploit",
    "poc",
    "proof-of-concept",
    "attack payload",
    "bypass step",
    "提权步骤",
    "绕过步骤",
    "攻击载荷",
    "具体恶意输入",
    "利用步骤",
)


class ContextSlicer(Protocol):
    """Duck-typed context-slicing capability injected by the composition root.

    Keeps the agent free of concrete analyzer imports (architecture rule):
    the provider returns an object with ``slices`` (each carrying
    file_path/start_line/end_line/source_kind/matched_symbol/text) and the
    agent only reads those facts.
    """

    def slice_project(self, root: Path, symbols: list[str], **kwargs: object) -> Any: ...


class CodeAuditAgent(BaseAgent):
    """Review code findings semantically without becoming a verdict authority."""

    name = "code_audit"

    def __init__(
        self,
        llm: BaseLLM | None = None,
        context_slice_provider: ContextSlicer | None = None,
    ) -> None:
        self.llm = llm
        self.context_slice_provider = context_slice_provider
        try:
            self._system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            self._system_prompt = (
                "仅复核本地授权的静态代码风险候选；只输出防御性 JSON，"
                "不得输出攻击性实现，最终结论由独立验证层给出。"
            )

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        candidates = [
            item
            for item in context.findings
            if item.metadata.get("audit_domain") == "software_code"
        ]
        evidence: list[Evidence] = []
        assessments: list[dict[str, Any]] = []
        for finding in candidates:
            slices = await self._collect_slices(task, finding)
            assessment = await self._assess(finding, slices)
            assessments.append(
                {
                    "finding_id": finding.vulnerability_id,
                    "review_result": assessment["review_result"],
                    "triggerability": assessment["triggerability"],
                    "recommended_severity": assessment["recommended_severity"],
                    "recommend_controlled_validation": assessment["recommended_severity"] in {"CRITICAL", "HIGH"},
                    "model_status": assessment["model_status"],
                    "context_slice_count": len(slices),
                }
            )
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task.task_id,
                    evidence_type=EvidenceType.MODEL_REASONING_SUMMARY,
                    source=self.name,
                    description=(
                        "Bounded semantic assessment of a software-code candidate; "
                        "auxiliary evidence only."
                    ),
                    data={"finding_id": finding.vulnerability_id, **assessment},
                    reliability=0.55,
                    created_by=self.name,
                )
            )
            for slice_item in slices:
                evidence.append(
                    Evidence(
                        evidence_id=new_evidence_id(),
                        task_id=task.task_id,
                        evidence_type=EvidenceType.CODE_SNIPPET,
                        source="context_slice_provider",
                        description=(
                            f"Bounded context slice ({slice_item.source_kind}) for "
                            f"{slice_item.matched_symbol or slice_item.file_path.name}; "
                            "factual provenance, not a verdict."
                        ),
                        data={
                            "file": str(slice_item.file_path),
                            "start_line": slice_item.start_line,
                            "end_line": slice_item.end_line,
                            "source_kind": slice_item.source_kind,
                            "matched_symbol": slice_item.matched_symbol,
                            "text": slice_item.text[:2000],
                        },
                        reliability=0.9,
                        created_by=self.name,
                    )
                )
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=AgentMessageType.ANALYSIS_RESULT,
            payload={
                "role": self.name,
                "reviewed_count": len(assessments),
                "assessments": assessments,
                "verdict_authority": "verification",
                "validation_schedule_authority": "supervisor_with_explicit_authorization",
                "defensive_only": True,
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(agent_name=self.name, messages=[message], evidence=evidence)

    async def _collect_slices(
        self,
        task: Task,
        finding: VulnerabilityCandidate,
    ) -> list[Any]:
        """Collect bounded context slices for a candidate (L1 adoption).

        Only reads the exact windows the review needs (definition + call
        site + guard); never whole files, never outside the admitted target
        root.  Slices are factual provenance appended as CODE_SNIPPET
        evidence; the model opinion stays auxiliary.
        """
        if self.context_slice_provider is None:
            return []
        project_root = Path(task.target.path)
        if not project_root.is_dir():
            return []
        symbols: list[str] = []
        location = finding.location
        if location is not None:
            symbols.append(str(getattr(location, "function", "") or ""))
        sink = str(finding.metadata.get("sink") or "")
        if sink:
            symbols.append(sink)
        entry = str(finding.metadata.get("entry_point") or "")
        if entry:
            symbols.append(entry)
        symbols = [s for s in dict.fromkeys(symbols) if s]
        if not symbols:
            return []
        result = self.context_slice_provider.slice_project(project_root, symbols)
        return list(getattr(result, "slices", []) or [])

    async def _assess(
        self,
        finding: VulnerabilityCandidate,
        slices: list[Any] | None = None,
    ) -> dict[str, Any]:
        fallback = self._fallback_assessment(finding)
        if self.llm is None:
            return fallback
        slices = slices or []
        request = {
            "candidate": {
                "finding_id": finding.vulnerability_id,
                "vulnerability_type": finding.vulnerability_type,
                "cwe_id": finding.cwe_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description[:800],
                "location": (
                    finding.location.model_dump(mode="json")
                    if finding.location is not None
                    else None
                ),
                "rule_id": finding.metadata.get("rule_id"),
                "sink": finding.metadata.get("sink"),
                "guard_observed": finding.metadata.get("guard_observed"),
                "taint_path": finding.metadata.get("taint_path", [])[:32],
                "cfg_path": finding.metadata.get("cfg_path", [])[:32],
                "snippet": str(finding.metadata.get("snippet") or "")[:500],
                "context_slices": [
                    {
                        "file": str(item.file_path),
                        "start_line": item.start_line,
                        "end_line": item.end_line,
                        "source_kind": item.source_kind,
                        "matched_symbol": item.matched_symbol,
                        "text": item.text[:800],
                    }
                    for item in slices[:8]
                ],
            },
            "instruction": "按系统提示中的固定 JSON schema 做防御性候选复核。",
        }
        try:
            raw = await self.llm.generate(
                json.dumps(request, ensure_ascii=False, separators=(",", ":")),
                system_prompt=self._system_prompt,
                max_tokens=700,
                temperature=0.0,
                response_format={"type": "json_object"},
                thinking={"type": "disabled"},
            )
            if self._contains_prohibited_content(raw):
                return {**fallback, "model_status": "safety_filtered"}
            parsed = json.loads(raw)
            if not isinstance(parsed, Mapping):
                raise ValueError("model assessment is not an object")
            return self._normalize_assessment(parsed, fallback)
        except Exception as exc:
            return {
                **fallback,
                "model_status": "fallback",
                "model_error_type": type(exc).__name__,
            }

    def _fallback_assessment(self, finding: VulnerabilityCandidate) -> dict[str, Any]:
        actions = [
            "在信任边界校验输入类型、长度、范围和空值。",
            "在敏感操作前增加支配该操作的容量或权限检查。",
            "补充错误处理、资源释放和脱敏审计日志。",
        ]
        summary = "补充输入边界检查、错误处理和最小权限校验，并进行独立复核。"
        taint_path = finding.metadata.get("taint_path")
        cfg_path = finding.metadata.get("cfg_path")
        supporting = []
        if isinstance(taint_path, list) and taint_path:
            supporting.append("静态分析记录了从输入源到敏感操作的污点路径。")
        if isinstance(cfg_path, list) and cfg_path:
            supporting.append("静态分析记录了函数入口到候选位置的控制流路径。")
        return {
            "review_result": "uncertain",
            "triggerability": "conditional" if supporting else "unknown",
            "recommended_severity": (
                finding.severity if finding.severity in _SEVERITIES else "MEDIUM"
            ),
            "confidence": round(float(finding.confidence), 3),
            "summary": "候选具备静态证据，但需由独立验证层结合受控运行结果定级。",
            "observed_guards": (
                ["静态分析观察到前置边界检查。"]
                if finding.metadata.get("guard_observed")
                else []
            ),
            "supporting_facts": supporting,
            "contradicting_facts": [],
            "missing_evidence": ["独立验证结论", "受控健壮性测试结果"],
            "remediation_summary": summary,
            "remediation_actions": actions,
            "safety": {"defensive_only": True, "prohibited_content_emitted": False},
            "model_status": "not_configured",
        }

    def _normalize_assessment(
        self,
        value: Mapping[str, Any],
        fallback: dict[str, Any],
    ) -> dict[str, Any]:
        def choice(key: str, allowed: frozenset[str]) -> str:
            candidate = str(value.get(key) or "")
            return candidate if candidate in allowed else str(fallback[key])

        def bounded_text(key: str, limit: int = 600) -> str:
            return str(value.get(key) or fallback.get(key) or "").replace("\x00", "")[:limit]

        def text_list(key: str) -> list[str]:
            raw = value.get(key)
            if not isinstance(raw, list):
                raw = fallback.get(key, [])
            return [str(item).replace("\x00", "")[:240] for item in list(raw)[:8]]

        try:
            confidence = min(1.0, max(0.0, float(value.get("confidence"))))
        except (TypeError, ValueError):
            confidence = float(fallback["confidence"])
        normalized = {
            "review_result": choice("review_result", _REVIEW_RESULTS),
            "triggerability": choice("triggerability", _TRIGGERABILITY),
            "recommended_severity": choice("recommended_severity", _SEVERITIES),
            "confidence": round(confidence, 3),
            "summary": bounded_text("summary"),
            "observed_guards": text_list("observed_guards"),
            "supporting_facts": text_list("supporting_facts"),
            "contradicting_facts": text_list("contradicting_facts"),
            "missing_evidence": text_list("missing_evidence"),
            "remediation_summary": bounded_text("remediation_summary"),
            "remediation_actions": text_list("remediation_actions"),
            "safety": {"defensive_only": True, "prohibited_content_emitted": False},
            "model_status": "accepted",
        }
        if self._contains_prohibited_content(json.dumps(normalized, ensure_ascii=False)):
            return {**fallback, "model_status": "safety_filtered"}
        return normalized

    @staticmethod
    def _contains_prohibited_content(value: str) -> bool:
        lowered = value.casefold()
        return any(marker in lowered for marker in _PROHIBITED_MARKERS)


__all__ = ["CodeAuditAgent"]
