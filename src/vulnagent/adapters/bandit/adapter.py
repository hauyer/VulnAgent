"""Bandit ToolAdapter (V0.6 third independent source engine).

Converts raw ``bandit -f json`` output into the neutral adapter boundary:
``ToolExecutionResult`` + ``NormalizedToolFinding`` + ``ProgramFact``, and maps
findings to provenance-carrying ``EvidenceV2`` with
``independence_group="bandit"`` (a third independent analysis family beside
native AST rules and semgrep).

Fail-safe by contract: missing tool, timeout, non-zero exit or malformed JSON
never raises through the pipeline — it returns ``success=False`` with the
reason preserved in ``metadata.error_kind`` / ``stderr_summary``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from vulnagent.contracts import (
    EvidenceType,
    EvidenceV2,
    NormalizedToolFinding,
    ProgramFact,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolHealth,
)
from vulnagent.contracts.common import utc_now

CAPABILITIES = frozenset({"source.scan.bandit"})

# bandit: 0 = scan clean, 1 = issues found; anything else is an engine error.
_BANDIT_OK_EXITS = frozenset({0, 1})
_DEFAULT_FINDING_RELIABILITY = 0.55


@dataclass
class RunnerResult:
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str | None = None


class CommandRunner(Protocol):
    def run(
        self,
        command: list[str],
        *,
        timeout_seconds: float,
        cwd: str | None = None,
    ) -> RunnerResult: ...


class SubprocessRunner:
    """Default runner using subprocess with a hard timeout and capped output."""

    def __init__(self, max_output_bytes: int = 4 * 1024 * 1024) -> None:
        self.max_output_bytes = max_output_bytes

    def run(
        self,
        command: list[str],
        *,
        timeout_seconds: float,
        cwd: str | None = None,
    ) -> RunnerResult:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=cwd,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "")[: self.max_output_bytes]
            stderr = (exc.stderr or "")[: self.max_output_bytes]
            return RunnerResult(stdout=stdout, stderr=stderr, timed_out=True)
        except FileNotFoundError as exc:
            return RunnerResult(error=f"executable not found: {exc}")
        except OSError as exc:
            return RunnerResult(error=f"os error: {exc}")

        stdout = (proc.stdout or "")[: self.max_output_bytes]
        stderr = (proc.stderr or "")[: self.max_output_bytes]
        return RunnerResult(
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )


def _truncate(text: str | None, limit: int = 2000) -> str | None:
    if not text:
        return None
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "..." + f"[truncated {len(text) - limit} chars]"


class BanditAdapter:
    """Adapter implementing the ``ToolAdapter`` boundary for Bandit."""

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self._executable = executable
        self._runner = runner or SubprocessRunner()
        self._last_errors: list[dict] | None = None

    # ------------------------------------------------------------------ ToolAdapter

    @property
    def name(self) -> str:
        return "bandit"

    @property
    def capabilities(self) -> set[str]:
        return set(CAPABILITIES)

    async def health(self) -> ToolHealth:
        prefix = self._command_prefix()
        result = self._runner.run([*prefix, "--version"], timeout_seconds=15.0)
        if result.timed_out:
            return ToolHealth(
                name=self.name,
                available=False,
                capabilities=sorted(CAPABILITIES),
                notes=["version probe timed out"],
            )
        if result.returncode == 0 and result.stdout.strip():
            return ToolHealth(
                name=self.name,
                available=True,
                version=result.stdout.strip().splitlines()[0],
                capabilities=sorted(CAPABILITIES),
                executable_path=self._resolved_executable_path(),
                configured=True,
            )
        return ToolHealth(
            name=self.name,
            available=False,
            capabilities=sorted(CAPABILITIES),
            notes=[f"version probe failed: {_truncate(result.stderr or result.error, 300)}"],
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        started_at = utc_now()
        result = ToolExecutionResult(
            run_id=request.run_id,
            capability=request.capability,
            provider=self.name,
            started_at=started_at,
        )

        target = Path(request.target_path)
        if not target.exists():
            result.stderr_summary = f"target not found: {request.target_path}"
            result.finished_at = utc_now()
            return result

        # -q keeps progress text off stdout so the JSON payload stays clean.
        command = [
            *self._command_prefix(),
            "-q",
            "-r",
            "-f",
            "json",
            str(target),
        ]
        if request.options.get("severity"):
            command += ["-l", str(request.options["severity"])]

        raw = self._runner.run(
            command,
            timeout_seconds=float(request.timeout_seconds),
            cwd=request.options.get("cwd"),
        )
        result.executed = True
        result.stdout_summary = _truncate(raw.stdout)
        result.stderr_summary = _truncate(raw.stderr)

        if raw.timed_out:
            findings, parse_error = self._parse_findings(raw.stdout, request.run_id)
            if parse_error is None:
                return self._finalize_success(result, findings, run_id=request.run_id, overrun=True)
            result.metadata["error_kind"] = "timeout"
            result.finished_at = utc_now()
            return result
        if raw.error:
            result.metadata["error_kind"] = "execution_error"
            result.metadata["error"] = raw.error
            result.finished_at = utc_now()
            return result
        if raw.returncode not in _BANDIT_OK_EXITS:
            result.metadata["error_kind"] = "nonzero_exit"
            result.metadata["returncode"] = raw.returncode
            result.finished_at = utc_now()
            return result

        findings, parse_error = self._parse_findings(raw.stdout, request.run_id)
        if parse_error is not None:
            result.metadata["error_kind"] = "malformed_json"
            result.metadata["error"] = parse_error
            result.finished_at = utc_now()
            return result

        return self._finalize_success(result, findings, run_id=request.run_id)

    def _finalize_success(
        self,
        result: ToolExecutionResult,
        findings: list[NormalizedToolFinding],
        *,
        run_id: str,
        overrun: bool = False,
    ) -> ToolExecutionResult:
        result.success = True
        result.findings = findings
        result.facts = [
            ProgramFact(
                fact_id=f"{run_id}-fact-{idx}",
                fact_type="match",
                language="python",
                file_path=finding.file_path,
                function_name=finding.function_name,
                line=finding.line_start,
                attributes={
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "cwe_id": finding.cwe_id,
                },
                producer=self.name,
                analysis_run_id=run_id,
            )
            for idx, finding in enumerate(findings)
        ]
        result.metadata["finding_count"] = len(findings)
        if overrun:
            result.metadata["overrun"] = True
        result.finished_at = utc_now()
        return result

    # ------------------------------------------------------------ finding mapping

    def _parse_findings(
        self,
        raw_json: str,
        run_id: str,
    ) -> tuple[list[NormalizedToolFinding], str | None]:
        try:
            payload = json.loads(raw_json)
        except Exception as exc:  # pragma: no cover - json errors vary
            return [], f"invalid json: {exc}"

        findings: list[NormalizedToolFinding] = []
        if payload.get("errors"):
            self._last_errors = payload["errors"]
        for idx, item in enumerate(payload.get("results", [])):
            cwe = self._cwe_id(item.get("issue_cwe"))
            findings.append(
                NormalizedToolFinding(
                    finding_id=f"{run_id}-f{idx}",
                    rule_id=item.get("test_id"),
                    rule_name=item.get("test_name"),
                    severity=(item.get("issue_severity") or "").upper() or None,
                    cwe_id=cwe,
                    file_path=item.get("filename"),
                    line_start=item.get("line_number"),
                    line_end=item.get("line_number"),
                    message=item.get("issue_text") or "",
                    raw={
                        "confidence": item.get("issue_confidence"),
                        "code": item.get("code"),
                        "more_info": item.get("more_info"),
                        "test_name": item.get("test_name"),
                    },
                )
            )
        return findings, None

    @staticmethod
    def _cwe_id(cwe_value: Any) -> str | None:
        if not cwe_value:
            return None
        if isinstance(cwe_value, dict):
            raw = cwe_value.get("id")
            return f"CWE-{raw}" if raw is not None else None
        return str(cwe_value)

    # -------------------------------------------------------------- evidence map

    def findings_to_evidence(
        self,
        result: ToolExecutionResult,
        *,
        task_id: str,
        session_id: str | None = None,
        reliability: float = _DEFAULT_FINDING_RELIABILITY,
    ) -> list[EvidenceV2]:
        """Map normalized findings to provenance-carrying EvidenceV2 items.

        All findings share ``independence_group="bandit"`` (one analysis
        family), so the verifier counts them as a single independent source.
        """
        evidence: list[EvidenceV2] = []
        for idx, finding in enumerate(result.findings):
            evidence.append(
                EvidenceV2(
                    evidence_id=f"{result.run_id}-ev-{idx}",
                    task_id=task_id,
                    session_id=session_id,
                    evidence_type=EvidenceType.SOURCE_LOCATION,
                    producer=self.name,
                    producer_version=None,
                    analysis_run_id=result.run_id,
                    derivation_id=f"{result.run_id}-{finding.finding_id}",
                    independence_group="bandit",
                    reliability=reliability,
                    artifact_refs=[item.artifact_id for item in result.artifacts],
                    description=finding.message or (finding.rule_id or "bandit finding"),
                    data={
                        "rule_id": finding.rule_id,
                        "rule_name": finding.rule_name,
                        "severity": finding.severity,
                        "cwe_id": finding.cwe_id,
                        "file_path": finding.file_path,
                        "line_start": finding.line_start,
                        "line_end": finding.line_end,
                    },
                )
            )
        return evidence

    # ------------------------------------------------------------------- helpers

    def _command_prefix(self) -> list[str]:
        if self._executable:
            return [self._executable]
        found = self._locate_executable()
        if found:
            return [found]
        return [sys.executable, "-m", "bandit"]

    def _resolved_executable_path(self) -> str | None:
        if self._executable:
            return self._executable
        found = self._locate_executable()
        if found:
            return found
        return f"{sys.executable} -m bandit"

    @staticmethod
    def _locate_executable() -> str | None:
        """Resolve a directly callable bandit executable.

        Prefers PATH, then the active environment's Scripts dir; falls back to
        ``python -m bandit`` (unlike semgrep, the module entry still works).
        """
        found = shutil.which("bandit")
        if found:
            return found
        scripts_dir = Path(sys.executable).parent
        candidate = scripts_dir / ("bandit.exe" if os.name == "nt" else "bandit")
        if candidate.is_file():
            return str(candidate)
        return None

    @staticmethod
    def new_run_id(task_id: str) -> str:
        """Allocate a fresh analysis run id for one adapter execution."""
        return f"{task_id}-bandit-{uuid.uuid4().hex[:12]}"
