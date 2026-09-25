"""WP6 unit: dossier state machine, redaction, unknown-target triage."""

from __future__ import annotations

from vulnagent.review import (
    DossierReceipt,
    DossierState,
    ExplorationLogEntry,
    ExplorationStage,
    ExploratorySession,
    HistoricalKnowledgeDedup,
    KnowledgeRecord,
    TriageDecision,
    redact,
    transition,
)


def _session(practice: bool = True) -> ExploratorySession:
    return ExploratorySession(
        session_id="s1",
        target_id="t1",
        target_kind="source",
        authorization={"static_read": True},
        practice_mode=practice,
    )


# -- state machine -----------------------------------------------------------


def test_state_machine_forward_only() -> None:
    session = _session(practice=False)
    assert transition(session, DossierState.SUBMITTED) is True
    assert session.state is DossierState.SUBMITTED
    # Cannot go backwards or skip steps.
    assert transition(session, DossierState.DRAFT) is False
    assert transition(session, DossierState.PUBLISHED_ACCEPTED) is False
    assert transition(session, DossierState.ACKNOWLEDGED) is True


def test_practice_mode_blocks_beyond_submitted() -> None:
    session = _session(practice=True)
    assert transition(session, DossierState.MAINTAINER_CONTACTED) is True
    assert transition(session, DossierState.ACKNOWLEDGED) is False
    assert transition(session, DossierState.FIXED) is False
    assert session.state is DossierState.MAINTAINER_CONTACTED


def test_receipts_are_explicit_not_auto_generated() -> None:
    session = _session(practice=False)
    assert session.receipts == []
    session.receipts.append(
        DossierReceipt(kind="ticket", reference="T-1", note="maintainer ack")
    )
    assert len(session.receipts) == 1


# -- redaction ----------------------------------------------------------------


def test_redaction_keeps_hashes_and_counts_not_details() -> None:
    session = _session()
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY,
            kind="candidate",
            detail="crash reproduced with trigger payload 0x41414141",
            candidate_ref="66a2d354b693c0a9488d0a2af5deff4829808f05b572ae0f65d9edfbb39e19c3",
        )
    )
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.NEGATIVE,
            kind="negative",
            detail="no novel candidate after dedup",
        )
    )
    draft = redact(session)
    assert draft.practice_mode is True
    assert draft.negative_count == 1
    assert draft.candidate_count == 1
    # The crash trigger payload is stripped; only a fingerprint remains.
    joined = draft.model_dump_json()
    assert "0x41414141" not in joined
    assert "66a2d354b693c0a9488d0a2af5deff4829808f05b572ae0f65d9edfbb39e19c3" not in joined
    assert "65d9edfbb39e19c3" in draft.candidate_refs[0]
    assert "Nothing has been submitted" in draft.disclosure_note


def test_redaction_tracks_review_pending_candidates_only() -> None:
    session = _session()
    # A known duplicate goes through triage but is not counted as a candidate.
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.TRIAGE,
            kind="triage",
            detail="c1: duplicate_known (matches upstream advisory)",
            candidate_ref="c1",
        )
    )
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.TRIAGE,
            kind="triage",
            detail="c2: needs_human_review (no match in historical knowledge)",
            candidate_ref="candidate-c2-abcdef1234567890",
        )
    )
    draft = redact(session)
    assert draft.candidate_count == 1
    assert draft.candidate_refs[0] == "abcdef1234567890"  # last-16 fingerprint


# -- triage -------------------------------------------------------------------


def test_triage_known_duplicate_vs_novel() -> None:
    dedup = HistoricalKnowledgeDedup(
        [KnowledgeRecord(cwe_id="CWE-78", fingerprint="subprocess", source="cvefixes", published=True)]
    )
    known = dedup.triage(
        {
            "candidate_id": "a",
            "cwe_id": "CWE-78",
            "description": "user input reaches subprocess.run",
            "evidence_count": 1,
        }
    )
    assert known.decision is TriageDecision.DUPLICATE_KNOWN
    assert known.matched_known[0].source == "cvefixes"

    novel = dedup.triage(
        {
            "candidate_id": "b",
            "cwe_id": "CWE-121",
            "description": "stack buffer overflow",
            "evidence_count": 2,
        }
    )
    assert novel.decision is TriageDecision.NEEDS_HUMAN_REVIEW
    assert any("human review" in reason for reason in novel.reasons)


def test_triage_insufficient_evidence() -> None:
    dedup = HistoricalKnowledgeDedup()
    result = dedup.triage(
        {
            "candidate_id": "c",
            "cwe_id": "CWE-1",
            "description": "vague claim, no evidence",
            "evidence_count": 0,
        }
    )
    assert result.decision is TriageDecision.INSUFFICIENT_EVIDENCE


def test_negative_note_never_counts_as_tn() -> None:
    note = HistoricalKnowledgeDedup.negative_note("t1", "no crash observed")
    assert note["counted_as_tn"] == "false"
    assert "no preset positive example" in note["reason"]
