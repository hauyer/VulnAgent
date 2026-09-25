"""WP6: exploratory sessions and redacted dossiers.

An exploratory session is an authorized unknown-target study with *no preset
positive example*: negative observations are recorded honestly and are never
counted as true negatives (the guide forbids that for the exploratory track).
A dossier carries the disclosure state machine
``draft -> maintainer_contacted -> submitted -> acknowledged -> fixed ->
published/accepted``; only human/maintainer receipts may advance it, the
system never auto-submits. Redaction strips trigger inputs, internal paths
and candidate detail while keeping necessary summaries and hashes, so the
public report exposes neither sensitive content nor undisclosed findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class DossierState(str, Enum):
    DRAFT = "draft"
    MAINTAINER_CONTACTED = "maintainer_contacted"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    FIXED = "fixed"
    PUBLISHED_ACCEPTED = "published/accepted"


# Valid transitions: strictly forward on the state machine. The system only
# ever records the receipt that a human provides; it never advances on its own.
_TRANSITIONS: dict[DossierState, set[DossierState]] = {
    DossierState.DRAFT: {
        DossierState.MAINTAINER_CONTACTED,
        DossierState.SUBMITTED,
    },
    DossierState.MAINTAINER_CONTACTED: {DossierState.SUBMITTED},
    DossierState.SUBMITTED: {DossierState.ACKNOWLEDGED},
    DossierState.ACKNOWLEDGED: {DossierState.FIXED},
    DossierState.FIXED: {DossierState.PUBLISHED_ACCEPTED},
    DossierState.PUBLISHED_ACCEPTED: set(),
}


class ExplorationStage(str, Enum):
    DISCOVERY = "discovery"
    TRIAGE = "triage"
    VERIFICATION = "verification"
    NEGATIVE = "negative"  # honest negative observation; never a TN


class ExplorationLogEntry(BaseModel):
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    stage: ExplorationStage
    kind: str  # candidate | tool_fact | negative | triage | receipt
    detail: str
    candidate_ref: str = ""
    verified: bool = False


class DossierReceipt(BaseModel):
    """A maintainer/platform receipt; only summaries survive redaction."""

    kind: str  # email | ticket | platform | none
    reference: str = ""  # sanitized reference, no credentials
    note: str = ""


class ExploratorySession(BaseModel):
    session_id: str
    target_id: str
    target_kind: str
    authorization: dict[str, Any]
    manifest_hash: str = ""
    tool_versions: dict[str, str] = Field(default_factory=dict)
    budget_seconds: int = 0
    random_seed: str = ""
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str = ""
    stop_reason: str = ""  # completed | timeout | budget | user_stopped
    state: DossierState = DossierState.DRAFT
    practice_mode: bool = Field(
        default=True,
        description="true when this is a course rehearsal; dossier is marked not-submitted",
    )
    entries: list[ExplorationLogEntry] = Field(default_factory=list)
    receipts: list[DossierReceipt] = Field(default_factory=list)


class RedactedDossier(BaseModel):
    """Public-facing summary; sensitive/undisclosed detail is stripped."""

    session_id: str
    target_id: str  # sanitized name only
    state: DossierState
    practice_mode: bool
    summary: str
    observation_count: int
    candidate_count: int
    negative_count: int
    candidate_refs: list[str] = Field(default_factory=list)  # hashes only
    timeline: list[dict[str, str]] = Field(default_factory=list)
    disclosure_note: str = (
        "This dossier is a course rehearsal. Nothing has been submitted to "
        "any maintainer or vulnerability platform."
    )


def transition(session: ExploratorySession, target: DossierState) -> bool:
    """Advance the state machine; human receipt is recorded beforehand.

    In practice mode nothing may advance past ``submitted`` (and the session
    is never auto-submitted -- the caller records the receipt explicitly).
    """
    if target == session.state:
        return False
    if target not in _TRANSITIONS[session.state]:
        return False
    if session.practice_mode and target in {
        DossierState.ACKNOWLEDGED,
        DossierState.FIXED,
        DossierState.PUBLISHED_ACCEPTED,
    }:
        return False
    session.state = target
    return True


def redact(session: ExploratorySession) -> RedactedDossier:
    """Produce the public summary, stripping sensitive detail and hashes-only refs."""

    def _safe_ref(ref: str) -> str:
        # Keep only a fingerprint-like token if present, else blank.
        return ref[-16:] if len(ref) >= 16 else ""

    candidates = [
        entry
        for entry in session.entries
        if entry.kind == "candidate"
        or (
            entry.kind == "triage"
            and "needs_human_review" in entry.detail
            and entry.candidate_ref
        )
    ]
    negatives = [
        entry for entry in session.entries if entry.stage is ExplorationStage.NEGATIVE
    ]
    timeline = [
        {"stage": entry.stage.value, "time": entry.timestamp, "kind": entry.kind}
        for entry in session.entries[-10:]
    ]
    return RedactedDossier(
        session_id=session.session_id,
        target_id=session.target_id,
        state=session.state,
        practice_mode=session.practice_mode,
        summary=(
            f"Exploratory study of authorized unknown target {session.target_id}; "
            f"{len(candidates)} candidate(s), {len(negatives)} negative "
            "observation(s), no preset positive example."
        ),
        observation_count=len(session.entries),
        candidate_count=len(candidates),
        negative_count=len(negatives),
        candidate_refs=[_safe_ref(e.candidate_ref) for e in candidates],
        timeline=timeline,
    )


class DossierStore:
    """Small JSON store for exploratory sessions (script/API backed)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        return self.root / f"{session_id}.json"

    def save(self, session: ExploratorySession) -> Path:
        path = self._path(session.session_id)
        path.write_text(
            session.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return path

    def load(self, session_id: str) -> ExploratorySession:
        return ExploratorySession.model_validate_json(
            self._path(session_id).read_text(encoding="utf-8")
        )

    def list_ids(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("*.json"))
