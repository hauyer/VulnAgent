"""Named workflow configurations (L9, roadmap §2.1).

Reusable, versioned configuration templates for the three main study routes —
source audit, known-CVE reproduction and external exploration — plus the
guided-variant track.  These are configuration names, not a second state
machine: agents still communicate through ``AgentMessage`` and the Supervisor
still owns routing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from vulnagent.intake.profile import StudyTrack


class WorkflowProfileName(StrEnum):
    SOURCE_AUDIT = "software_source_audit"
    KNOWN_CVE_REPLAY = "known_cve_replay"
    EXTERNAL_EXPLORATION = "external_unknown_exploration"
    GUIDED_VARIANT = "guided_variant_search"


@dataclass(frozen=True, slots=True)
class WorkflowProfile:
    """One versioned workflow configuration."""

    name: WorkflowProfileName
    version: str
    study_track: StudyTrack
    max_agent_steps: int
    analysis_retries: int
    allow_dynamic: bool
    allow_guided_hints: bool
    description: str

    def digest(self) -> dict:
        return {
            "workflow_profile": self.name.value,
            "workflow_version": self.version,
            "study_track": self.study_track.value,
            "max_agent_steps": self.max_agent_steps,
            "analysis_retries": self.analysis_retries,
            "allow_dynamic": self.allow_dynamic,
            "allow_guided_hints": self.allow_guided_hints,
        }


WORKFLOW_PROFILES: dict[WorkflowProfileName, WorkflowProfile] = {
    WorkflowProfileName.SOURCE_AUDIT: WorkflowProfile(
        name=WorkflowProfileName.SOURCE_AUDIT,
        version="1",
        study_track=StudyTrack.REAL_CVE_REPLAY,
        max_agent_steps=8,
        analysis_retries=1,
        allow_dynamic=False,
        allow_guided_hints=False,
        description="受控源码审计：静态分析 + 有界语义复核 + 独立验证，不动态执行",
    ),
    WorkflowProfileName.KNOWN_CVE_REPLAY: WorkflowProfile(
        name=WorkflowProfileName.KNOWN_CVE_REPLAY,
        version="1",
        study_track=StudyTrack.REAL_CVE_REPLAY,
        max_agent_steps=10,
        analysis_retries=2,
        allow_dynamic=True,
        allow_guided_hints=False,
        description="已知 CVE 双版本受控复现：构建 + 无害重放 + 修复对照 + 根因卡",
    ),
    WorkflowProfileName.EXTERNAL_EXPLORATION: WorkflowProfile(
        name=WorkflowProfileName.EXTERNAL_EXPLORATION,
        version="1",
        study_track=StudyTrack.EXTERNAL_UNKNOWN,
        max_agent_steps=12,
        analysis_retries=2,
        allow_dynamic=True,
        allow_guided_hints=False,
        description="外部未知目标探索：盲态语料 + 独立输入面 + 固定预算 + 判重",
    ),
    WorkflowProfileName.GUIDED_VARIANT: WorkflowProfile(
        name=WorkflowProfileName.GUIDED_VARIANT,
        version="1",
        study_track=StudyTrack.GUIDED_VARIANT,
        max_agent_steps=10,
        analysis_retries=1,
        allow_dynamic=True,
        allow_guided_hints=True,
        description="已知错误模式引导的变体搜索（独立 track，不并入盲态分数）",
    ),
}


def get_workflow_profile(name: str | WorkflowProfileName) -> WorkflowProfile:
    """Look up a workflow profile by name or short string."""
    key = WorkflowProfileName(name) if isinstance(name, str) else name
    return WORKFLOW_PROFILES[key]
