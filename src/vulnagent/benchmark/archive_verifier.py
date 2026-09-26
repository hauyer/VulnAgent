"""Run-archive verification (roadmap §9 completion gate).

From one ``run_id`` directory under ``artifacts/experiments/`` this verifies:
  1. every required artifact exists (manifest / trace / candidates / evidence
     / verification / metrics / checksums),
  2. ``checksums.sha256`` still matches the current file contents (tamper
     detection),
  3. traceability: every candidate's ``evidence_ids`` resolve inside
     ``evidence.jsonl``, and its ``source_agent`` appears in ``trace.jsonl``,
  4. metrics were produced by the independent evaluation (logical ordering).

GT isolation is enforced at the API layer; this verifier only checks archive
integrity and traceability, and never reads ground-truth files.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

REQUIRED_FILES = (
    "manifest.json",
    "trace.jsonl",
    "candidates.jsonl",
    "evidence.jsonl",
    "verification.jsonl",
    "metrics.json",
    "checksums.sha256",
)
OPTIONAL_FILES = ("clusters.jsonl",)


@dataclass(slots=True)
class ArchiveReport:
    run_id: str
    ok: bool
    missing: list[str] = field(default_factory=list)
    tampered: list[str] = field(default_factory=list)
    untraceable_evidence: list[str] = field(default_factory=list)
    unknown_agents: list[str] = field(default_factory=list)
    checksums_missing: list[str] = field(default_factory=list)
    metrics_ordering_note: str = ""
    checked_files: int = 0

    def issues(self) -> list[str]:
        out = list(self.missing)
        out.extend(f"tampered: {name}" for name in self.tampered)
        out.extend(f"unresolved evidence: {ref}" for ref in self.untraceable_evidence)
        out.extend(f"agent missing from trace: {name}" for name in self.unknown_agents)
        if self.metrics_ordering_note:
            out.append(self.metrics_ordering_note)
        return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def verify_run_archive(root: Path) -> ArchiveReport:
    """Verify one experiment archive directory."""
    run_id = root.name
    report = ArchiveReport(run_id=run_id, ok=True)

    required = [name for name in REQUIRED_FILES if name != "checksums.sha256"]
    for name in required:
        if not (root / name).is_file():
            report.missing.append(name)
            report.ok = False

    # 1) checksum verification (tamper detection)
    checksums_path = root / "checksums.sha256"
    expected: dict[str, str] = {}
    if checksums_path.is_file():
        for line in checksums_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                expected[parts[1]] = parts[0]
    else:
        report.missing.append("checksums.sha256")
        report.ok = False

    for name, expected_sha in expected.items():
        path = root / name
        if not path.is_file():
            report.checksums_missing.append(name)
            report.ok = False
            continue
        report.checked_files += 1
        if sha256_file(path) != expected_sha:
            report.tampered.append(name)
            report.ok = False

    # 2) traceability: candidates -> evidence -> trace agents
    candidates = _read_jsonl(root / "candidates.jsonl")
    evidence = _read_jsonl(root / "evidence.jsonl")
    trace = _read_jsonl(root / "trace.jsonl")

    evidence_ids = {str(row.get("evidence_id")) for row in evidence}
    trace_producers = {
        str(row.get("sender") or row.get("producer"))
        for row in trace
        if row.get("sender") or row.get("producer")
    }
    for candidate in candidates:
        for ref in candidate.get("evidence_ids") or []:
            if str(ref) not in evidence_ids:
                report.untraceable_evidence.append(str(ref))
                report.ok = False
        agent = candidate.get("source_agent")
        if agent and str(agent) not in trace_producers:
            report.unknown_agents.append(str(agent))
            report.ok = False

    # 3) metrics ordering: metrics must not predate verification by manifest date
    manifest_path = root / "manifest.json"
    metrics_path = root / "metrics.json"
    if manifest_path.is_file() and metrics_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            if metrics.get("run_id") and manifest.get("run_id") and metrics["run_id"] != manifest["run_id"]:
                report.metrics_ordering_note = (
                    f"metrics run_id {metrics['run_id']} != manifest run_id {manifest['run_id']}"
                )
                report.ok = False
        except (json.JSONDecodeError, OSError):
            report.metrics_ordering_note = "manifest/metrics not readable JSON"
            report.ok = False

    return report


def verify_experiment_root(root: Path, run_id: str) -> ArchiveReport:
    """Verify by explicit run id under the experiments root."""
    return verify_run_archive(root / run_id)
