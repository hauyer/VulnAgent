"""WP6: authorized unknown-target exploration experiment.

Treats self-authored teaching fixtures as *authorized unknown targets* with
no preset positive example (exploratory track). The run:
  1. opens an ExploratorySession (authorization, budgets, seed, tool versions)
  2. discovers candidates via the real static chain (native + Semgrep/Bandit)
     and, when clang is available, the real libFuzzer/ASan dynamic chain
  3. triages every candidate against a historical-knowledge table
     (engine never asserts novelty; anything kept goes to human review)
  4. records negative observations without counting them as true negatives
  5. writes a redacted dossier draft, explicitly marked not-submitted

Reproducible:  python -m experiments.run_unknown_exploration
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.normalize import external_finding_to_candidate
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import FuzzRequest, ProjectInput, ToolExecutionRequest
from vulnagent.fuzz.libfuzzer import RealLibFuzzerEngine
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

LOGGER = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "artifacts" / "experiments" / "wp6-exploration"

# Historical-knowledge table (upstream advisory / CVEfixes style records).
# The cp_parse case is intentionally absent so the crash candidate survives
# as an unverified novel candidate for human review (engine never asserts
# novelty on its own).
_KNOWLEDGE = [
    KnowledgeRecord(
        cwe_id="CWE-78",
        fingerprint="subprocess",
        source="upstream_advisory",
        published=True,
    ),
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _static_discovery(
    case_id: str,
    target: Path,
    session: ExploratorySession,
    out: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    task_id = f"wp6-{case_id}"

    parsed = await SourceProjectParser().analyze(
        ProjectInput(
            task_id=task_id,
            target_id=case_id,
            project_path=str(target.parent),
        )
    )
    findings = await PythonSourceAuditor().audit(parsed)
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY,
            kind="tool_fact",
            detail=f"native auditor scanned {len(parsed.files)} file(s), "
            f"{len(findings)} finding(s)",
        )
    )
    for finding in findings:
        loc = finding.location
        rows.append(
            {
                "candidate_id": f"{task_id}-native-{uuid.uuid4().hex[:8]}",
                "cwe_id": finding.cwe_id,
                "vulnerability_type": finding.vulnerability_type,
                "location": f"{Path(loc.file_path).name}:{loc.line_start}",
                "description": finding.description,
                "evidence_count": 1,
                "note": "native auditor",
            }
        )

    for name, cls in (("semgrep", SemgrepAdapter), ("bandit", BanditAdapter)):
        adapter = cls()
        request = ToolExecutionRequest(
            run_id=f"{task_id}-{name}",
            task_id=task_id,
            session_id=None,
            capability=f"source.scan.{name}",
            target_path=str(target),
            authorized=True,
            timeout_seconds=120,
        )
        result = await adapter.execute(request)
        session.entries.append(
            ExplorationLogEntry(
                stage=ExplorationStage.DISCOVERY,
                kind="tool_fact",
                detail=f"{name} executed={result.executed} success={result.success} "
                f"findings={len(result.findings)}",
            )
        )
        if not result.success or not result.executed:
            rows.append(
                {
                    "candidate_id": f"{task_id}-{name}-unavailable",
                    "cwe_id": "",
                    "vulnerability_type": "",
                    "location": "",
                    "evidence_count": 0,
                    "status": "unavailable" if not result.executed else "invalid",
                    "note": f"{name} executed={result.executed} success={result.success}",
                }
            )
            continue
        for finding in result.findings:
            cand = external_finding_to_candidate(
                result, finding, task_id=task_id, target_id=case_id
            )
            loc = cand.location
            rows.append(
                {
                    "candidate_id": cand.vulnerability_id,
                    "cwe_id": cand.cwe_id,
                    "vulnerability_type": cand.vulnerability_type,
                    "location": f"{Path(loc.file_path).name}:{loc.line_start}",
                    "description": cand.description,
                    "evidence_count": 1,
                    "note": f"{name} adapter",
                }
            )
    return rows


async def _dynamic_discovery(
    case_id: str,
    target: Path,
    session: ExploratorySession,
    out: Path,
) -> list[dict[str, Any]]:
    from vulnagent.sandbox.compiler import compile_libfuzzer_target, locate_clang

    clang = locate_clang()
    if clang is None:
        session.entries.append(
            ExplorationLogEntry(
                stage=ExplorationStage.DISCOVERY,
                kind="tool_fact",
                detail="clang toolchain unavailable; dynamic chain not run",
            )
        )
        return [
            {
                "candidate_id": f"wp6-{case_id}-notrun",
                "cwe_id": "",
                "vulnerability_type": "",
                "location": "",
                "evidence_count": 0,
                "status": "unavailable",
                "note": "clang toolchain unavailable",
            }
        ]

    work = out / "work"
    work.mkdir(parents=True, exist_ok=True)
    build = compile_libfuzzer_target(
        target,
        work / "build",
        clang=clang,
        opt_level="-O0",
    )
    if not build.compiled:
        return [
            {
                "candidate_id": f"wp6-{case_id}-buildfail",
                "cwe_id": "",
                "vulnerability_type": "",
                "location": "",
                "evidence_count": 0,
                "status": "invalid",
                "note": f"build failed: {build.reason}",
            }
        ]
    session.tool_versions["clang"] = build.engine_version

    seeds = REPO_ROOT / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse" / "seeds"
    result = await RealLibFuzzerEngine().run(
        FuzzRequest(
            task_id=f"wp6-{case_id}",
            target_id=case_id,
            target_path=build.binary_path or "",
            authorized=True,
            metadata={
                "runs": 50000,
                "max_len": 64,
                "seed": 7,
                "seed_dir": str(seeds),
                "work_dir": str(work / "run"),
                "artifact_dir": str(work / "artifacts"),
                "compile_command_hash": build.compile_command_hash,
                "engine_version": build.engine_version,
            },
        )
    )
    session.entries.append(
        ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY,
            kind="tool_fact",
            detail=f"libFuzzer runs={result.metadata.get('runs')} "
            f"crashes={result.crashes} "
            f"sanitizer={result.metadata.get('sanitizer_kind')} "
            f"fixed={result.metadata.get('fixed_outcome')}",
        )
    )
    if result.crashes:
        crash_ref = result.metadata.get("crash_input_sha256", "")
        session.entries.append(
            ExplorationLogEntry(
                stage=ExplorationStage.DISCOVERY,
                kind="candidate",
                detail="crash reproduced; fixed-version contrast clean",
                candidate_ref=crash_ref,
            )
        )
        return [
            {
                "candidate_id": f"wp6-{case_id}-crash",
                "cwe_id": "CWE-121",
                "vulnerability_type": result.metadata.get("sanitizer_kind", "crash"),
                "location": "vuln.c:16",
                "evidence_count": 2,
                "note": f"crash_input={crash_ref} "
                f"replay={result.metadata.get('replay_count')} "
                f"fixed={result.metadata.get('fixed_outcome')}",
            }
        ]
    return [
        {
            "candidate_id": f"wp6-{case_id}-nocrash",
            "cwe_id": "",
            "vulnerability_type": "",
            "location": "",
            "evidence_count": 0,
            "note": "no crash observed",
        }
    ]


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    path.write_text(lines, encoding="utf-8")


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")


async def main() -> None:
    out = DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    # Authorized unknown targets (self-authored fixtures used as unknowns).
    targets = [
        {
            "target_id": "py-cmd-001-vulnerable",
            "target_kind": "source",
            "path": REPO_ROOT / "benchmarks" / "source" / "py-cmd-001-vulnerable" / "app.py",
            "authorization": {
                "static_read": True,
                "file_transform": False,
                "dynamic_run": False,
                "data_export": False,
                "statement": "local self-authored fixture; static analysis only",
            },
        },
        {
            "target_id": "cp_parse-vuln",
            "target_kind": "binary",
            "path": REPO_ROOT / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse" / "vuln.c",
            "authorization": {
                "static_read": True,
                "file_transform": False,
                "dynamic_run": True,
                "data_export": False,
                "statement": "local self-authored fixture; dynamic run in isolated sandbox",
            },
        },
        {
            "target_id": "py-cmd-002-clean",
            "target_kind": "source",
            "path": REPO_ROOT / "benchmarks" / "source" / "py-cmd-002-clean" / "app.py",
            "authorization": {
                "static_read": True,
                "file_transform": False,
                "dynamic_run": False,
                "data_export": False,
                "statement": "local self-authored fixture; static analysis only",
            },
        },
    ]

    session = ExploratorySession(
        session_id=f"wp6-exploration-{uuid.uuid4().hex[:8]}",
        target_id=", ".join(t["target_id"] for t in targets),
        target_kind="mixed",
        authorization={
            "mode": "exploratory",
            "note": "authorized unknown targets; no preset positive example",
        },
        manifest_hash=hashlib.sha256(
            "\n".join(sorted(_sha256(t["path"]) for t in targets)).encode()
        ).hexdigest(),
        tool_versions={
            "python": platform.python_version(),
            "native_auditor": "v0.4",
        },
        budget_seconds=600,
        random_seed="wp6-seed-1",
        practice_mode=True,
    )

    dedup = HistoricalKnowledgeDedup(_KNOWLEDGE)
    all_candidates: list[dict[str, Any]] = []

    for target in targets:
        case_id = target["target_id"]
        if target["target_kind"] == "source":
            rows = await _static_discovery(case_id, target["path"], session, out)
        else:
            rows = await _dynamic_discovery(case_id, target["path"], session, out)
        all_candidates.extend(rows)

        case_decisions: list[str] = []
        for row in rows:
            if row.get("status") in {"unavailable", "invalid"}:
                session.entries.append(
                    ExplorationLogEntry(
                        stage=ExplorationStage.DISCOVERY,
                        kind="tool_fact",
                        detail=f"{case_id}: {row.get('note', row.get('status'))}",
                    )
                )
                continue
            if not row.get("cwe_id"):
                # Negative observation: recorded honestly, never a TN.
                session.entries.append(
                    ExplorationLogEntry(
                        stage=ExplorationStage.NEGATIVE,
                        kind="negative",
                        detail=f"{case_id}: {row.get('note', 'no candidate')}",
                    )
                )
                row["negative"] = True
                case_decisions.append("negative")
                continue
            result = dedup.triage(row)
            case_decisions.append(result.decision.value)
            session.entries.append(
                ExplorationLogEntry(
                    stage=ExplorationStage.TRIAGE,
                    kind="triage",
                    detail=f"{case_id} {row['candidate_id']}: "
                    f"{result.decision.value} ({'; '.join(result.reasons)})",
                    candidate_ref=row["candidate_id"],
                )
            )

        # No candidate on this target survived as a novel candidate.
        if not case_decisions or not any(
            d == "needs_human_review" for d in case_decisions
        ):
            session.entries.append(
                ExplorationLogEntry(
                    stage=ExplorationStage.NEGATIVE,
                    kind="negative",
                    detail=(
                        f"{case_id}: no novel candidate after historical dedup; "
                        "awaiting human review, not counted as TN"
                    ),
                )
            )

    session.finished_at = datetime.now(timezone.utc).isoformat()
    session.stop_reason = "completed"

    store = DossierStore(out / "dossiers")
    store.save(session)

    _write_jsonl(out / "candidates.jsonl", all_candidates)
    _write_jsonl(
        out / "triage.jsonl",
        [
            {
                "candidate_id": r["candidate_id"],
                "cwe_id": r.get("cwe_id", ""),
                "decision": (
                    dedup.triage(r).decision.value
                    if r.get("cwe_id") and not r.get("negative")
                    else ("negative" if r.get("negative") else "not_run")
                ),
                "note": r.get("note", ""),
            }
            for r in all_candidates
        ],
    )

    redacted = redact(session)
    _write_yaml(out / "dossier_redacted.yaml", redacted.model_dump(mode="json"))

    # Human receipt drives the only allowed practice-mode transition.
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
        "practice_mode": session.practice_mode,
        "state": session.state.value,
        "disclosure_note": redacted.disclosure_note,
        "observations": len(session.entries),
        "candidates": len(all_candidates),
        "negatives": sum(1 for r in all_candidates if r.get("negative")),
        "artifacts": {
            "session": str(store._path(session.session_id)),
            "candidates": str(out / "candidates.jsonl"),
            "triage": str(out / "triage.jsonl"),
            "redacted_draft": str(out / "dossier_redacted.yaml"),
        },
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
