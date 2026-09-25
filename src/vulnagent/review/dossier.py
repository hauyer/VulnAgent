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
    """A maintainer/platform receipt; only summaries survive redaction.

    ``kind=none`` is never a valid receipt for advancing the state machine.
    """

    kind: str  # email | ticket | platform | phone | none
    reference: str = ""  # sanitized reference (ticket id / receipt no.), no credentials
    note: str = ""


# Valid receipt kinds for each real-state transition target. A ``kind=none``
# receipt or a missing reference where required does not advance the machine.
_RECEIPT_KINDS: dict[DossierState, set[str]] = {
    DossierState.MAINTAINER_CONTACTED: {"email", "ticket", "platform", "phone"},
    DossierState.SUBMITTED: {"ticket", "platform"},
    DossierState.ACKNOWLEDGED: {"email", "ticket", "platform"},
    DossierState.FIXED: {"email", "ticket", "platform"},
    DossierState.PUBLISHED_ACCEPTED: {"platform"},
}
_REFERENCE_REQUIRED = {DossierState.SUBMITTED, DossierState.PUBLISHED_ACCEPTED}


def _valid_receipt_for(receipt: DossierReceipt, target: DossierState) -> bool:
    if receipt.kind == "none":
        return False
    if receipt.kind not in _RECEIPT_KINDS.get(target, set()):
        return False
    if target in _REFERENCE_REQUIRED and not receipt.reference.strip():
        return False
    return True


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
        description="true when this is a course rehearsal; the real state stays "
        "draft and any demonstrated flow is recorded in simulated_state only",
    )
    simulated_state: DossierState | None = Field(
        default=None,
        description="practice-mode demonstration state, always clearly labeled "
        "SIMULATED; never a real contact or submission",
    )
    entries: list[ExplorationLogEntry] = Field(default_factory=list)
    receipts: list[DossierReceipt] = Field(default_factory=list)


class RedactedDossier(BaseModel):
    """Public-facing summary; sensitive/undisclosed detail is stripped."""

    session_id: str
    target_id: str  # sanitized name only
    state: DossierState
    practice_mode: bool
    simulated_state: DossierState | None = None
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


def _last_valid_receipt(session: ExploratorySession) -> DossierReceipt | None:
    """Most recent receipt recorded by a human that is not kind=none."""
    for receipt in reversed(session.receipts):
        if receipt.kind != "none":
            return receipt
    return None


def transition(
    session: ExploratorySession,
    target: DossierState,
    *,
    receipt: DossierReceipt | None = None,
) -> bool:
    """Advance the disclosure state machine under strict honesty rules.

    - Real mode (``practice_mode=False``): every advance requires an explicit
      valid human receipt (``kind != none`` and, for submitted / published,
      a non-empty reference). Without it the transition is refused.
    - Practice mode (``practice_mode=True``): the real ``state`` never moves
      from ``draft``; a demonstration advance is recorded only in
      ``simulated_state`` and must be labeled SIMULATED everywhere.
    - ``kind=none`` is never a valid receipt.
    """
    if session.practice_mode:
        # Demonstration flow: advance along the simulated chain only.
        current = session.simulated_state or DossierState.DRAFT
        if target not in _TRANSITIONS[current]:
            return False
        session.simulated_state = target
        return True

    # Real mode: edge + an explicit, target-matching human receipt.
    if target not in _TRANSITIONS[session.state]:
        return False
    if receipt is None or not _valid_receipt_for(receipt, target):
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
    simulated = session.simulated_state if session.practice_mode else None
    disclosure_note = (
        "SIMULATED disclosure rehearsal: the state machine was demonstrated "
        "only. Nothing has been submitted to any maintainer or vulnerability "
        "platform; real state remains draft."
        if simulated is not None and session.state is DossierState.DRAFT
        else (
            "This dossier is a course rehearsal. Nothing has been submitted to "
            "any maintainer or vulnerability platform."
        )
    )
    return RedactedDossier(
        session_id=session.session_id,
        target_id=session.target_id,
        state=session.state,
        practice_mode=session.practice_mode,
        simulated_state=simulated,
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
        disclosure_note=disclosure_note,
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
