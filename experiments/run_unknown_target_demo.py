"""P1-1: authorized unknown-target rehearsal on a real unpublished tool.

Reuses the WP6 exploration machinery (session / static discovery / historical
dedup / redacted dossier / disclosure state machine) against a self-authored,
never-released tool (benchmarks/unknown/unpublished-log-merge) treated as an
authorized unknown target: no preset positive example, candidates survive only
via historical dedup, and the dossier ends in the honest UNSUBMITTED state.

Reproducible:  python -m experiments.run_unknown_target_demo
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vulnagent.review import (
    DossierReceipt,
    DossierState,
    DossierStore,
    ExplorationLogEntry,
    ExplorationStage,
    ExploratorySession,
    HistoricalKnowledgeDedup,
    KnowledgeRecord,
    redact,
    transition,
)

from experiments.run_unknown_exploration import (
    _sha256,
    _static_discovery,
    _write_jsonl,
    _write_yaml,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "artifacts" / "experiments" / "wp8-unknown-demo"

# Historical-knowledge table: CWE-502 is intentionally NOT listed, so the
# deserialization candidate survives as a novel candidate for human review.
_KNOWLEDGE = [
    KnowledgeRecord(
        cwe_id="CWE-78",
        fingerprint="subprocess",
        source="upstream_advisory",
        published=True,
    ),
]


async def main() -> None:
    out = OUT
    out.mkdir(parents=True, exist_ok=True)

    target_path = (
        REPO_ROOT / "benchmarks" / "unknown" / "unpublished-log-merge" / "app.py"
    )
    target = {
        "target_id": "unpublished-log-merge",
        "target_kind": "source",
        "path": target_path,
        "authorization": {
            "static_read": True,
            "file_transform": False,
            "dynamic_run": False,
            "data_export": False,
            "statement": "self-authored unpublished tool; static analysis only",
        },
    }

    session = ExploratorySession(
        session_id=f"wp8-unknown-demo-{uuid.uuid4().hex[:8]}",
        target_id=target["target_id"],
        target_kind="source",
        authorization={
            "mode": "exploratory",
            "note": "authorized unknown target: unpublished self-authored tool",
        },
        manifest_hash=hashlib.sha256(_sha256(target["path"]).encode()).hexdigest(),
        tool_versions={
            "python": platform.python_version(),
            "native_auditor": "v0.4",
        },
        budget_seconds=300,
        random_seed="wp8-unknown-demo-1",
        practice_mode=True,
    )

    dedup = HistoricalKnowledgeDedup(_KNOWLEDGE)
    rows = await _static_discovery(
        target["target_id"], target["path"], session, out
    )
    all_candidates: list[dict] = []
    case_decisions: list[str] = []
    for row in rows:
        all_candidates.append(row)
        if row.get("status") in {"unavailable", "invalid"}:
            continue
        if not row.get("cwe_id"):
            row["negative"] = True
            case_decisions.append("negative")
            continue
        result = dedup.triage(row)
        case_decisions.append(result.decision.value)
        session.entries.append(
            ExplorationLogEntry(
                stage=ExplorationStage.TRIAGE,
                kind="triage",
                detail=f"{row['candidate_id']}: {result.decision.value} "
                f"({'; '.join(result.reasons)})",
                candidate_ref=row["candidate_id"],
            )
        )

    session.finished_at = datetime.now(timezone.utc).isoformat()
    session.stop_reason = "completed"
    store = DossierStore(out / "dossiers")
    store.save(session)

    _write_jsonl(out / "candidates.jsonl", all_candidates)
    redacted = redact(session)
    _write_yaml(out / "dossier_redacted.yaml", redacted.model_dump(mode="json"))

    advanced = transition(session, DossierState.MAINTAINER_CONTACTED)
    if advanced:
        session.receipts.append(
            DossierReceipt(
                kind="none",
                reference="",
                note="course rehearsal; no maintainer contacted",
            )
        )
        store.save(session)

    summary = {
        "session_id": session.session_id,
        "target": target["target_id"],
        "practice_mode": session.practice_mode,
        "state": session.state.value,
        "disclosure_note": redacted.disclosure_note,
        "observations": len(session.entries),
        "candidates": len(all_candidates),
        "novel_candidates": sum(1 for d in case_decisions if d == "needs_human_review"),
        "artifacts": {
            "session": str(store._path(session.session_id)),
            "candidates": str(out / "candidates.jsonl"),
            "redacted_draft": str(out / "dossier_redacted.yaml"),
        },
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "metrics.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
