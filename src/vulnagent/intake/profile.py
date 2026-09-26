"""Target profile and capability routing (L3 / roadmap §3.1 A).

``TargetProfile`` is the agent-visible digest of an admitted target: an opaque
id (no CVE/patch hints), a study track, a bounded work root, the pinned hash
and the exact permissions/budgets the runtime may use.  The Supervisor reads a
profile *hint* to narrow the allowed ``AgentRoute`` subset and single-stage
budget; the profile itself never writes ``TaskStatus`` or the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from vulnagent.intake.models import IntakeDecision, TargetManifest

STUDY_TRACKS = {
    "real_cve_replay",
    "exploitgym_adapted_discovery",
    "external_unknown",
    "guided_variant_search",
}


class StudyTrack(StrEnum):
    REAL_CVE_REPLAY = "real_cve_replay"
    EXPLOITGYM_ADAPTED = "exploitgym_adapted_discovery"
    EXTERNAL_UNKNOWN = "external_unknown"
    GUIDED_VARIANT = "guided_variant_search"


@dataclass(frozen=True, slots=True)
class TargetProfile:
    opaque_target_id: str
    track: StudyTrack
    target_kind: str  # source / binary
    language: str | None
    root: Path
    target_sha256: str
    static_read: bool
    dynamic_run: bool
    max_seconds: int
    max_execs: int | None

    def route_subset(self) -> set[str]:
        """Suggested allowed routes for this profile; Router stays the judge."""
        from vulnagent.agent_runtime.router import AgentRoute

        base = {
            AgentRoute.PLANNER.value,
            AgentRoute.SOURCE_ANALYSIS.value,
            AgentRoute.BINARY_ANALYSIS.value,
            AgentRoute.VERIFICATION.value,
            AgentRoute.REVIEWER.value,
            AgentRoute.REPORT.value,
        }
        if self.target_kind == "binary":
            base.add(AgentRoute.PROGRAM_RESTORATION.value)
        if self.dynamic_run:
            base.add(AgentRoute.FUZZ.value)
        if self.track is StudyTrack.GUIDED_VARIANT:
            base.add(AgentRoute.CODE_AUDIT.value)
        return base

    def digest(self) -> dict:
        """Small metadata-safe summary for ``Task.target.metadata``."""
        return {
            "opaque_target_id": self.opaque_target_id,
            "track": self.track.value,
            "target_kind": self.target_kind,
            "language": self.language,
            "target_sha256": self.target_sha256,
            "static_read": self.static_read,
            "dynamic_run": self.dynamic_run,
            "max_seconds": self.max_seconds,
            "max_execs": self.max_execs,
            "profile_version": "1",
        }


class DefaultTargetProfiler:
    """Deterministic profile from an intake decision + manifest (side-effect free)."""

    def __init__(
        self,
        default_max_seconds: int = 300,
        default_max_execs: int | None = 1000,
    ) -> None:
        self.default_max_seconds = default_max_seconds
        self.default_max_execs = default_max_execs

    def profile(
        self,
        decision: IntakeDecision,
        manifest: TargetManifest,
        *,
        track: StudyTrack = StudyTrack.EXTERNAL_UNKNOWN,
        root: Path | None = None,
    ) -> TargetProfile:
        if not decision.accepted:
            raise ValueError(
                f"target {manifest.sample_id} is not admitted: {decision.issues}"
            )
        target_path = Path(decision.normalized_path or manifest.target_path)
        return TargetProfile(
            opaque_target_id=f"opaque-{manifest.sample_id}",
            track=track,
            target_kind=(
                "source" if not manifest.target_path.lower().endswith((".exe", ".dll", ".bin")) else "binary"
            ),
            language=manifest.language,
            root=root or target_path.parent,
            target_sha256=decision.checked_sha256 or manifest.target_sha256,
            static_read=manifest.authorization.static_read,
            dynamic_run=manifest.authorization.dynamic_run,
            max_seconds=self.default_max_seconds,
            max_execs=self.default_max_execs,
        )

    def profile_from_digest(self, digest: dict) -> TargetProfile:
        """Rebuild a profile from a previously stored metadata digest."""
        if digest.get("profile_version") != "1":
            raise ValueError("unknown profile_version")
        return TargetProfile(
            opaque_target_id=str(digest["opaque_target_id"]),
            track=StudyTrack(str(digest["track"])),
            target_kind=str(digest["target_kind"]),
            language=digest.get("language"),
            root=Path(str(digest["root"])) if digest.get("root") else Path.cwd(),
            target_sha256=str(digest["target_sha256"]),
            static_read=bool(digest.get("static_read", False)),
            dynamic_run=bool(digest.get("dynamic_run", False)),
            max_seconds=int(digest.get("max_seconds", 300)),
            max_execs=digest.get("max_execs"),
        )
