"""Semgrep ToolAdapter (V0.5 first external engine integration).

Converts raw ``semgrep scan --json`` output into the neutral adapter boundary:
``ToolExecutionResult`` + ``NormalizedToolFinding`` + ``ProgramFact``, and maps
findings to provenance-carrying ``EvidenceV2`` (``independence_group="semgrep"``).

Fail-safe by contract: a missing tool, timeout, non-zero error exit or malformed
JSON never raises through the pipeline — it returns ``success=False`` with the
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

CAPABILITIES = frozenset({"source.scan.semgrep"})

# semgrep exit codes: 0 = no findings, 1 = findings found; anything else is an
# engine-level error and must not be treated as a clean scan.
_SEMGREP_OK_EXITS = frozenset({0, 1})

_DEFAULT_FINDING_RELIABILITY = 0.6


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


class SemgrepAdapter:
    """Adapter implementing the ``ToolAdapter`` boundary for Semgrep."""

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: CommandRunner | None = None,
        default_config: str = "auto",
    ) -> None:
        self._executable = executable
        self._runner = runner or SubprocessRunner()
        self._default_config = default_config

    # ------------------------------------------------------------------ ToolAdapter

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def capabilities(self) -> set[str]:
        return set(CAPABILITIES)

    async def health(self) -> ToolHealth:
        prefix = self._command_prefix()
        result = self._runner.run([*prefix, "--version"], timeout_seconds=10.0)
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

        config = request.options.get("config", self._default_config)
        command = [
            *self._command_prefix(),
            "scan",
            "--json",
            "--no-git-ignore",
            "--config",
            str(config),
            str(target),
        ]
        if request.options.get("severity"):
            command += ["--severity", str(request.options["severity"])]

        raw = self._runner.run(
            command,
            timeout_seconds=float(request.timeout_seconds),
            cwd=request.options.get("cwd"),
        )
        result.executed = True
        result.stdout_summary = _truncate(raw.stdout)
        result.stderr_summary = _truncate(raw.stderr)

        if raw.timed_out:
            # The engine may have written its complete JSON before the wall-clock
            # budget expired.  Accept a full, parseable result and note the
            # overrun instead of discarding it; only a partial/garbage output
            # degrades to a timeout failure.
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
        if raw.returncode not in _SEMGREP_OK_EXITS:
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
        """Attach findings/facts and mark the run successful."""
        result.success = True
        result.findings = findings
        result.facts = [
            ProgramFact(
                fact_id=f"{run_id}-fact-{idx}",
                fact_type="match",
                language=finding.raw.get("language"),
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
        for idx, item in enumerate(payload.get("results", [])):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            cwe = self._first_cwe(metadata.get("cwe"))
            start = (item.get("start") or {}).get("line")
            end = (item.get("end") or {}).get("line")
            findings.append(
                NormalizedToolFinding(
                    finding_id=f"{run_id}-f{idx}",
                    rule_id=item.get("check_id"),
                    rule_name=extra.get("rule_id") or item.get("check_id"),
                    severity=(extra.get("severity") or "").upper() or None,
                    cwe_id=cwe,
                    file_path=item.get("path"),
                    line_start=start,
                    line_end=end,
                    message=extra.get("message") or "",
                    raw={
                        "language": extra.get("language"),
                        "fix": metadata.get("fix"),
                        "confidence": metadata.get("confidence"),
                        "sink": metadata.get("vuln_sink") or metadata.get("sink"),
                        "metadata": metadata,
                    },
                )
            )
        return findings, None

    @staticmethod
    def _first_cwe(cwe_value: Any) -> str | None:
        if not cwe_value:
            return None
        if isinstance(cwe_value, list):
            return str(cwe_value[0]) if cwe_value else None
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

        All findings share ``independence_group="semgrep"`` (one analysis
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
                    independence_group="semgrep",
                    reliability=reliability,
                    artifact_refs=[item.artifact_id for item in result.artifacts],
                    description=finding.message or (finding.rule_id or "semgrep finding"),
                    data={
                        "rule_id": finding.rule_id,
                        "rule_name": finding.rule_name,
                        "severity": finding.severity,
                        "cwe_id": finding.cwe_id,
                        "file_path": finding.file_path,
                        "line_start": finding.line_start,
                        "line_end": finding.line_end,
                        "sink": finding.raw.get("sink"),
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
        # Legacy fallback; deprecated by semgrep >= 1.38 but kept for older pins.
        return [sys.executable, "-m", "semgrep"]

    def _resolved_executable_path(self) -> str | None:
        if self._executable:
            return self._executable
        found = self._locate_executable()
        if found:
            return found
        return f"{sys.executable} -m semgrep"

    @staticmethod
    def _locate_executable() -> str | None:
        """Resolve a directly callable semgrep executable.

        Prefers PATH, then the active environment's Scripts dir (Windows venv
        installs land in ``.venv\\Scripts\\semgrep.exe``, which is not on PATH
        unless the venv is activated).  ``python -m semgrep`` is intentionally
        last: semgrep >= 1.38 refuses it.
        """
        found = shutil.which("semgrep")
        if found:
            return found
        scripts_dir = Path(sys.executable).parent
        candidate = scripts_dir / ("semgrep.exe" if os.name == "nt" else "semgrep")
        if candidate.is_file():
            return str(candidate)
        return None

    @staticmethod
    def new_run_id(task_id: str) -> str:
        """Allocate a fresh analysis run id for one adapter execution."""
        return f"{task_id}-semgrep-{uuid.uuid4().hex[:12]}"
