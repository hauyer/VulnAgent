"""§9: run-archive verification tests (benchmark/archive_verifier)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vulnagent.benchmark.archive_verifier import (
    REQUIRED_FILES,
    sha256_file,
    verify_run_archive,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_archive(tmp_path: Path) -> Path:
    """Create a valid archive: manifest/trace/candidates/evidence/verification/metrics/checksums."""
    root = tmp_path / "run-1"
    root.mkdir()
    manifest = {"run_id": "run-1", "status": "completed"}
    trace = [{"sender": "source_analysis", "message_type": "analysis_result"}]
    candidates = [
        {
            "vulnerability_id": "vuln-1",
            "source_agent": "source_analysis",
            "evidence_ids": ["ev-1"],
        }
    ]
    evidence = [{"evidence_id": "ev-1", "evidence_type": "code_snippet"}]
    verification = [{"vulnerability_id": "vuln-1", "status": "CONFIRMED"}]
    metrics = {"run_id": "run-1", "candidate_count": 1}
    files = {
        "manifest.json": json.dumps(manifest),
        "trace.jsonl": "\n".join(json.dumps(r) for r in trace),
        "candidates.jsonl": "\n".join(json.dumps(r) for r in candidates),
        "evidence.jsonl": "\n".join(json.dumps(r) for r in evidence),
        "verification.jsonl": "\n".join(json.dumps(r) for r in verification),
        "metrics.json": json.dumps(metrics),
    }
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    checksums = "\n".join(f"{_sha(v.encode())}  {k}" for k, v in files.items())
    (root / "checksums.sha256").write_text(checksums, encoding="utf-8")
    return root


class TestVerifyRunArchive:
    def test_valid_archive_passes(self, tmp_path: Path) -> None:
        root = _write_archive(tmp_path)
        report = verify_run_archive(root)
        assert report.ok is True
        assert report.missing == []
        assert report.tampered == []
        assert report.checked_files == len(REQUIRED_FILES) - 1  # minus checksums itself

    def test_missing_required_file_fails(self, tmp_path: Path) -> None:
        root = _write_archive(tmp_path)
        (root / "metrics.json").unlink()
        report = verify_run_archive(root)
        assert report.ok is False
        assert "metrics.json" in report.missing

    def test_tampered_file_fails(self, tmp_path: Path) -> None:
        root = _write_archive(tmp_path)
        (root / "candidates.jsonl").write_text("tampered", encoding="utf-8")
        report = verify_run_archive(root)
        assert report.ok is False
        assert "candidates.jsonl" in report.tampered

    def test_untraceable_evidence_fails(self, tmp_path: Path) -> None:
        root = _write_archive(tmp_path)
        (root / "evidence.jsonl").write_text(
            json.dumps({"evidence_id": "ev-other"}),
            encoding="utf-8",
        )
        # checksum mismatch too; re-issue checksums so only traceability fails
        files = [p.name for p in root.iterdir() if p.name != "checksums.sha256"]
        lines = []
        for name in files:
            data = (root / name).read_bytes()
            lines.append(f"{_sha(data)}  {name}")
        (root / "checksums.sha256").write_text("\n".join(lines), encoding="utf-8")
        report = verify_run_archive(root)
        assert "ev-1" in report.untraceable_evidence
        assert report.ok is False

    def test_agent_missing_from_trace_fails(self, tmp_path: Path) -> None:
        root = _write_archive(tmp_path)
        (root / "trace.jsonl").write_text(
            json.dumps({"sender": "other_agent"}),
            encoding="utf-8",
        )
        files = [p.name for p in root.iterdir() if p.name != "checksums.sha256"]
        lines = [f"{_sha((root / n).read_bytes())}  {n}" for n in files]
        (root / "checksums.sha256").write_text("\n".join(lines), encoding="utf-8")
        report = verify_run_archive(root)
        assert "source_analysis" in report.unknown_agents
        assert report.ok is False

    def test_sha256_file_deterministic(self, tmp_path: Path) -> None:
        p = tmp_path / "x.bin"
        p.write_bytes(b"data")
        assert sha256_file(p) == _sha(b"data")
