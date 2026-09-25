"""P0-A migration: correct practice-mode dossier states without rewriting history.

Before the receipt-strictness fix, practice sessions recorded
``state=maintainer_contacted`` with a ``kind=none`` receipt. The fix (P0-A)
requires real state to stay ``draft`` in practice mode. This script:
  1. leaves every original dossier file untouched (history preserved),
  2. writes ``<session_id>_corrected.json`` (real state draft, old state moved
     to simulated_state, disclosure note updated),
  3. writes ``<session_id>_correction.json`` explaining what changed and why,
  4. appends a ``correction`` record to the enclosing summary.json (if present).

Run from the repository root:
  python scripts/migrate_dossier_states.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vulnagent.review.dossier import (
    DossierReceipt,
    DossierState,
    DossierStore,
    ExplorationLogEntry,
    ExplorationStage,
    ExploratorySession,
    redact,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

_TARGET_SUMMARY_DIRS = [
    REPO_ROOT / "artifacts" / "experiments" / "wp8-zero-day",
    REPO_ROOT / "artifacts" / "experiments" / "wp8-unknown-demo",
    REPO_ROOT / "artifacts" / "experiments" / "wp6-exploration",
]


def _migrate_one(store: DossierStore, session_id: str) -> Path | None:
    path = store._path(session_id)
    session = store.load(session_id)
    if not session.practice_mode:
        return None
    if session.state is DossierState.DRAFT:
        return None

    old_state = session.state
    session.state = DossierState.DRAFT
    session.simulated_state = old_state
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.TRIAGE,
            kind="tool_fact",
            detail=(
                "P0-A correction: practice-mode real state reset to draft; "
                f"demonstrated flow recorded as simulated_state={old_state.value}"
            ),
        )
    )
    store.save(session)
    corrected = store._path(f"{session_id}_corrected")
    corrected.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    correction = {
        "session_id": session_id,
        "original_file": path.name,
        "original_state": old_state.value,
        "corrected_file": corrected.name,
        "corrected_state": DossierState.DRAFT.value,
        "simulated_state": old_state.value,
        "reason": (
            "P0-A honesty fix: practice mode must keep the real state at draft; "
            "kind=none is not a valid receipt and cannot advance the real machine"
        ),
        "rule": "docs guide section 6 (national vulnerability database & coordinated disclosure)",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    note = path.with_name(f"{session_id}_correction.json")
    note.write_text(
        json.dumps(correction, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return note


def main() -> int:
    migrated = 0
    for directory in _TARGET_SUMMARY_DIRS:
        store = DossierStore(directory / "dossiers")
        for session_id in store.list_ids():
            if session_id.endswith("_corrected"):
                continue
            note = _migrate_one(store, session_id)
            if note is not None:
                migrated += 1
                print(f"corrected {session_id} -> {note.name}")

        summary_path = directory / "summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("state") not in (None, "draft"):
                summary["corrected_state"] = "draft"
                summary["disclosure_correction"] = (
                    "P0-A honesty fix: real state reset to draft; demonstrated "
                    "flow recorded as simulated_state only"
                )
                summary_path.write_text(
                    json.dumps(summary, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                print(f"annotated {summary_path}")
    print(f"migrated {migrated} dossier(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
