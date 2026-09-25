"""V0.8 Dynamic Confirmation: runtime precheck analyzer.

Scans Python source with the self-authored precheck rules and emits
``VulnerabilityCandidate`` records (CWE-193 unchecked index, CWE-369
divide-by-zero) that seed the dynamic-confirmation pipeline.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from vulnagent.contracts import (
    ProjectInput,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)

from .rules import (
    PrecheckFinding,
    _collect_taint_sources,
    check_divide_by_zero,
    check_unchecked_index,
)

logger = logging.getLogger(__name__)


class RuntimePrecheckAnalyzer:
    """Static source prechecks for runtime-confirmable candidates."""

    def __init__(self) -> None:
        self._counter = 0

    def audit(self, project_input: ProjectInput) -> list[VulnerabilityCandidate]:
        root = Path(project_input.project_path)
        if root.is_file():
            files = [root]
        else:
            files = [p for p in root.rglob("*.py") if "__pycache__" not in str(p)]
        candidates: list[VulnerabilityCandidate] = []
        for path in sorted(files):
            try:
                text = path.read_text(encoding="utf-8")
                tree = ast.parse(text, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError) as exc:
                logger.debug("runtime precheck skip %s: %s", path, exc)
                continue
            findings = self._analyze_tree(tree)
            for finding in findings:
                self._counter += 1
                candidates.append(
                    VulnerabilityCandidate(
                        vulnerability_id=f"precheck-{self._counter}",
                        task_id=project_input.task_id,
                        title=finding.title,
                        vulnerability_type=finding.vulnerability_type,
                        cwe_id=finding.cwe_id,
                        description=finding.description,
                        target_id=project_input.target_id,
                        location=VulnerabilityLocation(
                            file_path=str(path),
                            line_start=finding.line,
                            line_end=finding.line,
                        ),
                        source_agent="source_audit",
                        source_type="source",
                        producer="python-runtime-precheck",
                        confidence=finding.confidence,
                        severity="WARNING",
                        metadata={
                            "sink": finding.sink,
                            "source_kinds": finding.source_kinds,
                            "analysis_engine": "runtime-precheck",
                        },
                    )
                )
        return candidates

    def _analyze_tree(self, tree: ast.AST) -> list[PrecheckFinding]:
        findings: list[PrecheckFinding] = []
        containers: list[ast.AST] = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        # Module-level statements (scripts like `print(1 // n)` at top level).
        containers.append(tree)
        seen: set[tuple[int, str]] = set()
        for container in containers:
            tainted = _collect_taint_sources(container)
            for finding in [*check_divide_by_zero(container, tainted), *check_unchecked_index(container, tainted)]:
                key = (finding.line, finding.cwe_id)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        return findings
