"""0-day-capability rehearsal: real fuzz discovery on authorized unknown targets.

For each authorized unknown target (self-authored, vulnerability location NOT
annotated — treated as unknown):
  1. compile the vulnerable + fixed variants (libFuzzer + ASan, -O0)
  2. run the real libFuzzer engine and capture a real sanitizer crash
  3. replay the crash input independently and contrast against the fixed build
  4. static pass (clang --analyze) as a second source of candidates
  5. historical dedup (no preset positive for these CWE families -> novel)
  6. redacted dossier with an honest UNSUBMITTED disclosure state

This demonstrates the *capability* to discover previously-unknown-in-target
vulnerabilities end to end on authorized local targets. It does NOT claim to
have discovered a real-world 0-day.

Reproducible:  python -m experiments.run_zero_day_rehearsal
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vulnagent.contracts import FuzzRequest
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
from vulnagent.sandbox.compiler import compile_libfuzzer_target, locate_clang

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "artifacts" / "experiments" / "wp8-zero-day"

# Historical-knowledge table: no entries for these CWE families, so any real
# crash survives as a novel candidate for human review (engine never asserts
# novelty on its own).
_KNOWLEDGE = [
    KnowledgeRecord(
        cwe_id="CWE-78",
        fingerprint="subprocess",
        source="upstream_advisory",
        published=True,
    ),
]

_TARGETS = [
    {
        "case_id": "fuzz-slot-table",
        "cwe_id": "CWE-787",
        "path": REPO_ROOT / "benchmarks" / "unknown" / "fuzz-slot-table",
        "runs": 40000,
    },
    {
        "case_id": "fuzz-kv-store",
        "cwe_id": "CWE-416",
        "path": REPO_ROOT / "benchmarks" / "unknown" / "fuzz-kv-store",
        "runs": 20000,
    },
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_clang_analyze(source: Path) -> list[str]:
    """Static pass: clang --analyze (real checker, findings are candidates)."""
    clang = locate_clang()
    if clang is None:
        return ["clang toolchain unavailable"]
    try:
        proc = subprocess.run(
            [str(clang), "--analyze", "-Xanalyzer", "-analyzer-output=text",
             str(source)],
            capture_output=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"analyzer launch failed: {exc}"]
    text = (proc.stdout or b"").decode(errors="replace") + "\n" + \
        (proc.stderr or b"").decode(errors="replace")
    lines = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.startswith("ANALYZE")
    ]
    return lines or ["no analyzer findings"]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8",
    )


def _write_yaml(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")


async def main() -> None:
    out = OUT
    out.mkdir(parents=True, exist_ok=True)

    session = ExploratorySession(
        session_id=f"wp8-zero-day-{uuid.uuid4().hex[:8]}",
        target_id=", ".join(t["case_id"] for t in _TARGETS),
        target_kind="binary",
        authorization={
            "mode": "exploratory",
            "note": "authorized unknown targets; vulnerability location "
                    "not annotated; dynamic runs in local sandbox",
        },
        manifest_hash=hashlib.sha256(
            "\n".join(sorted(t["path"].name for t in _TARGETS)).encode()
        ).hexdigest(),
        tool_versions={
            "python": platform.python_version(),
            "engine": "libfuzzer+asan",
        },
        budget_seconds=1800,
        random_seed="wp8-zero-day-1",
        practice_mode=True,
    )

    dedup = HistoricalKnowledgeDedup(_KNOWLEDGE)
    all_candidates: list[dict] = []
    engine = RealLibFuzzerEngine()
    clang = locate_clang()

    for target in _TARGETS:
        case_id = target["case_id"]
        src = target["path"] / "vuln.c"
        fix_src = target["path"] / "fix.c"
        work = out / "work" / case_id
        work.mkdir(parents=True, exist_ok=True)

        # --- compile vulnerable + fixed variants ---
        build = compile_libfuzzer_target(src, work / "build_vuln", clang=clang,
                                         opt_level="-O0")
        fix_build = compile_libfuzzer_target(fix_src, work / "build_fix",
                                             clang=clang, opt_level="-O0")
        if not build.compiled:
            session.entries.append(ExplorationLogEntry(
                stage=ExplorationStage.DISCOVERY, kind="tool_fact",
                detail=f"{case_id}: build failed: {build.reason}",
            ))
            all_candidates.append({
                "candidate_id": f"wp8-{case_id}-buildfail",
                "cwe_id": "", "vulnerability_type": "", "location": "",
                "status": "invalid", "note": f"build failed: {build.reason}",
            })
            continue
        session.tool_versions[f"{case_id}_clang"] = build.engine_version

        # --- static pass (clang --analyze) ---
        analyzer_rows = _run_clang_analyze(src)
        session.entries.append(ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY, kind="tool_fact",
            detail=f"{case_id}: clang --analyze -> {len(analyzer_rows)} line(s)",
        ))

        # --- real fuzz ---
        seeds = target["path"] / "seeds"
        fuzz = await engine.run(FuzzRequest(
            task_id=f"wp8-{case_id}",
            target_id=case_id,
            target_path=build.binary_path or "",
            authorized=True,
            metadata={
                "runs": target["runs"],
                "max_len": 256,
                "seed": 11,
                "seed_dir": str(seeds),
                "work_dir": str(work / "run"),
                "artifact_dir": str(work / "artifacts"),
                "fix_binary": fix_build.binary_path,
                "compile_command_hash": build.compile_command_hash,
                "engine_version": build.engine_version,
            },
        ))
        session.entries.append(ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY, kind="tool_fact",
            detail=f"{case_id}: libFuzzer runs={fuzz.metadata.get('runs')} "
                   f"crashes={fuzz.crashes} sanitizer="
                   f"{fuzz.metadata.get('sanitizer_kind')} "
                   f"fixed={fuzz.metadata.get('fixed_outcome')} "
                   f"cov={fuzz.metadata.get('coverage')}",
        ))

        if fuzz.crashes and fuzz.metadata.get("crash_input_sha256"):
            crash_sha = fuzz.metadata["crash_input_sha256"]
            # copy crash artifact next to the summary for the user
            artifact_dir = work / "artifacts"
            crash_files = sorted(artifact_dir.glob("crash-*"),
                                 key=lambda p: p.stat().st_mtime)
            crash_copy = None
            if crash_files:
                crash_copy = out / "crashes" / f"{case_id}-crash"
                crash_copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(crash_files[-1], crash_copy)
            session.entries.append(ExplorationLogEntry(
                stage=ExplorationStage.DISCOVERY, kind="candidate",
                detail=f"{case_id}: real sanitizer crash reproduced; "
                       f"fixed-version contrast={fuzz.metadata.get('fixed_outcome')}",
                candidate_ref=crash_sha,
            ))
            row = {
                "candidate_id": f"wp8-{case_id}-crash",
                "cwe_id": target["cwe_id"],
                "vulnerability_type": fuzz.metadata.get("sanitizer_kind"),
                "location": "vuln.c (unannotated)",
                "evidence_count": 3,
                "note": f"real crash: {fuzz.metadata.get('crash_signature')} "
                        f"stack={fuzz.metadata.get('stack_hash')} "
                        f"replay={fuzz.metadata.get('replay_count')} "
                        f"fixed={fuzz.metadata.get('fixed_outcome')} "
                        f"analyzer_lines={len(analyzer_rows)}",
            }
            all_candidates.append(row)
            result = dedup.triage(row)
            session.entries.append(ExplorationLogEntry(
                stage=ExplorationStage.TRIAGE, kind="triage",
                detail=f"{case_id} {row['candidate_id']}: "
                       f"{result.decision.value} ({'; '.join(result.reasons)})",
                candidate_ref=row["candidate_id"],
            ))
        else:
            session.entries.append(ExplorationLogEntry(
                stage=ExplorationStage.NEGATIVE, kind="negative",
                detail=f"{case_id}: no crash observed in "
                       f"{target['runs']} runs (honest negative, not a TN)",
            ))
            all_candidates.append({
                "candidate_id": f"wp8-{case_id}-nocrash",
                "cwe_id": "", "vulnerability_type": "", "location": "",
                "negative": True,
                "note": f"runs={fuzz.metadata.get('runs')} "
                        f"sanitizer={fuzz.metadata.get('sanitizer_kind')} "
                        f"executed={fuzz.metadata.get('executed')}",
            })

    session.finished_at = datetime.now(timezone.utc).isoformat()
    session.stop_reason = "completed"
    store = DossierStore(out / "dossiers")
    store.save(session)

    _write_jsonl(out / "candidates.jsonl", all_candidates)

    advanced = transition(session, DossierState.MAINTAINER_CONTACTED)
    if advanced:
        # Practice mode: real state stays draft; the demonstrated flow is
        # recorded in simulated_state only and labeled SIMULATED.
        session.receipts.append(DossierReceipt(
            kind="none", reference="",
            note="course rehearsal; no maintainer contacted",
        ))
        store.save(session)

    redacted = redact(session)
    _write_yaml(out / "dossier_redacted.yaml", redacted.model_dump(mode="json"))

    summary = {
        "session_id": session.session_id,
        "practice_mode": session.practice_mode,
        "state": session.state.value,
        "simulated_state": (
            session.simulated_state.value if session.simulated_state else None
        ),
        "disclosure_note": redacted.disclosure_note,
        "targets": [t["case_id"] for t in _TARGETS],
        "observations": len(session.entries),
        "candidates": len(all_candidates),
        "crashes": [r["candidate_id"] for r in all_candidates
                    if r.get("candidate_id", "").endswith("-crash")],
        "honesty": {
            "scope": "real libFuzzer+ASan discovery on authorized self-authored "
                     "unknown targets; not a real-world 0-day claim",
            "novelty": "no preset positive in knowledge table; candidates "
                       "require human review",
            "disclosure": "SIMULATED state machine rehearsal only; real state "
                          "is draft, nothing submitted",
        },
        "artifacts": {
            "session": str(store._path(session.session_id)),
            "candidates": str(out / "candidates.jsonl"),
            "redacted_draft": str(out / "dossier_redacted.yaml"),
            "crash_dir": str(out / "crashes"),
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
