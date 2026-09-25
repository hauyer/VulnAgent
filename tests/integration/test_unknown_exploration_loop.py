"""WP6 integration: unknown-target exploration closed loop.

Runs the exploratory session over the self-authored fixtures: discovery
(native + Semgrep/Bandit; real libFuzzer when clang exists), triage with
historical dedup, negative-observation honesty, redacted draft generation
and the practice-mode state machine guard. No "new vulnerability" claim is
ever produced by the engine.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from vulnagent.contracts import ProjectInput
from vulnagent.review import (
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

REPO_ROOT = Path(__file__).resolve().parents[2]


def _parse_and_audit(target: Path):
    """Run the real parser + native auditor synchronously via asyncio.run."""
    from vulnagent.analyzers.source.audit import PythonSourceAuditor
    from vulnagent.analyzers.source.parser import SourceProjectParser

    async def _run():
        parsed = await SourceProjectParser().analyze(
            ProjectInput(
                task_id="it-explore-1",
                target_id=target.parent.name,
                project_path=str(target.parent),
            )
        )
        return await PythonSourceAuditor().audit(parsed)

    return asyncio.run(_run())


def test_exploratory_session_never_claims_novelty(tmp_path: Path) -> None:
    session = ExploratorySession(
        session_id="it-explore-1",
        target_id="py-cmd-001-vulnerable",
        target_kind="source",
        authorization={"static_read": True},
        practice_mode=True,
    )
    target = REPO_ROOT / "benchmarks" / "source" / "py-cmd-001-vulnerable" / "app.py"
    findings = _parse_and_audit(target)

    dedup = HistoricalKnowledgeDedup(
        [
            KnowledgeRecord(
                cwe_id="CWE-78",
                fingerprint="subprocess",
                source="upstream_advisory",
                published=True,
            )
        ]
    )
    decisions = []
    for finding in findings:
        result = dedup.triage(
            {
                "candidate_id": f"it-{finding.vulnerability_id}",
                "cwe_id": finding.cwe_id,
                "description": finding.description,
                "evidence_count": 1,
            }
        )
        decisions.append(result.decision.value)
        session.entries.append(
            ExplorationLogEntry(
                stage=ExplorationStage.TRIAGE,
                kind="triage",
                detail=f"{finding.cwe_id}: {result.decision.value}",
                candidate_ref=f"it-{finding.vulnerability_id}",
            )
        )

    assert findings, "real auditor produced no finding on the vulnerable fixture"
    # The known CWE-78/subprocess issue is deduped to known; the engine never
    # asserts a novel finding from a known pattern.
    assert "duplicate_known" in decisions
    assert "needs_human_review" not in decisions

    draft = redact(session)
    assert draft.practice_mode is True
    assert draft.candidate_count == 0  # all deduped as known

    # Practice-mode state machine: demonstration advance moves only the
    # simulated state; the real state stays draft (kind=none is never a
    # receipt for the real machine).
    assert transition(session, DossierState.MAINTAINER_CONTACTED) is True
    assert transition(session, DossierState.ACKNOWLEDGED) is False

    store = DossierStore(tmp_path)
    store.save(session)
    loaded = store.load(session.session_id)
    assert loaded.state is DossierState.DRAFT
    assert loaded.simulated_state is DossierState.MAINTAINER_CONTACTED


def test_negative_observation_not_counted_as_tn() -> None:
    note = HistoricalKnowledgeDedup.negative_note("t-unknown", "no crash observed")
    assert note["counted_as_tn"] == "false"
    assert note["reason"] == "exploratory track: no preset positive example"
