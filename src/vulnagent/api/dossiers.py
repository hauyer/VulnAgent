"""WP6: research API for exploratory dossiers.

Endpoints manage exploratory sessions, append observation logs, advance the
disclosure state machine (only on a human-provided receipt) and generate the
redacted public draft. The system never auto-submits; practice sessions stay
at draft/submitted and are explicitly marked not-submitted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException

from vulnagent.review.dossier import (
    DossierReceipt,
    DossierState,
    DossierStore,
    ExplorationLogEntry,
    ExplorationStage,
    ExploratorySession,
    redact,
    transition,
)

router = APIRouter()


def _store() -> DossierStore:
    repository_root = Path(__file__).resolve().parents[3]
    return DossierStore(repository_root / "artifacts" / "dossiers")


@router.post("/dossiers")
async def create_dossier(
    session: Annotated[ExploratorySession, Body()],
) -> dict:
    store = _store()
    store.save(session)
    return {"session_id": session.session_id, "state": session.state.value}


@router.post("/dossiers/{session_id}/entries")
async def append_entry(session_id: str, entry: ExplorationLogEntry) -> dict:
    store = _store()
    try:
        session = store.load(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dossier not found")
    session.entries.append(entry)
    store.save(session)
    return {"session_id": session_id, "entries": len(session.entries)}


@router.post("/dossiers/{session_id}/receipt")
async def record_receipt(session_id: str, receipt: DossierReceipt) -> dict:
    """Record a maintainer receipt; the system does not create receipts."""
    store = _store()
    try:
        session = store.load(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dossier not found")
    session.receipts.append(receipt)
    store.save(session)
    return {"session_id": session_id, "receipts": len(session.receipts)}


@router.post("/dossiers/{session_id}/state")
async def advance_state(session_id: str, target_state: str) -> dict:
    """Advance the disclosure state machine.

    Real mode requires a valid human receipt already recorded on the session
    (kind != none; reference required for submitted / published). Practice
    mode only moves ``simulated_state`` and the real state stays draft.
    """
    store = _store()
    try:
        parsed = DossierState(target_state)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"unknown state {target_state}")
    try:
        session = store.load(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dossier not found")
    basis = next(
        (r for r in reversed(session.receipts) if r.kind != "none"),
        None,
    )
    advanced = transition(session, parsed, receipt=basis)
    if not advanced:
        raise HTTPException(
            status_code=422,
            detail=(
                f"illegal transition from {session.state.value} to {parsed.value}"
                " (real mode requires a valid human receipt)"
            ),
        )
    store.save(session)
    return {
        "session_id": session_id,
        "state": session.state.value,
        "simulated_state": (
            session.simulated_state.value if session.simulated_state else None
        ),
        "practice_mode": session.practice_mode,
    }


@router.get("/dossiers/{session_id}/redacted")
async def redacted_draft(session_id: str) -> dict:
    store = _store()
    try:
        session = store.load(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="dossier not found")
    return redact(session).model_dump()
