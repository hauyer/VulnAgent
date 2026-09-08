"""Provider-neutral application dependency definitions.

This module groups public capability Protocol implementations required
by the VulnAgent composition root.

No concrete analyzer, fuzzer, verifier, report generator or external
provider implementation may be imported here.
"""

from dataclasses import dataclass
from typing import Any

from vulnagent.contracts import (
    BinaryAnalyzer,
    FuzzEngine,
    ReportGenerator,
    SourceAuditor,
    SourceParser,
    VulnerabilityVerifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CapabilityBundle:
    """Injected domain capabilities required by VulnAgent.

    Members are typed against public Contracts/Protocols rather than
    concrete implementations.

    Replacing a Mock implementation with a real implementation should
    therefore require only a Composition Root change.
    """

    source_parser: SourceParser
    source_auditor: SourceAuditor

    binary_analyzer: BinaryAnalyzer

    fuzz_engine: FuzzEngine

    verifier: VulnerabilityVerifier

    report_generator: ReportGenerator

    def __post_init__(self) -> None:
        """Perform small structural checks on injected capabilities.

        Existing Contracts are intentionally not changed merely to make
        them runtime-checkable.  Bootstrap instead performs explicit
        fail-fast checks for required async operations.
        """

        self._require_callable(
            self.source_parser,
            "analyze",
            "source_parser",
        )

        self._require_callable(
            self.source_auditor,
            "audit",
            "source_auditor",
        )

        self._require_callable(
            self.binary_analyzer,
            "analyze",
            "binary_analyzer",
        )

        self._require_callable(
            self.fuzz_engine,
            "run",
            "fuzz_engine",
        )

        self._require_callable(
            self.verifier,
            "verify",
            "verifier",
        )

        self._require_callable(
            self.report_generator,
            "generate",
            "report_generator",
        )

    @staticmethod
    def _require_callable(
        dependency: Any,
        method_name: str,
        dependency_name: str,
    ) -> None:
        """Ensure one injected capability exposes its required method."""

        method = getattr(
            dependency,
            method_name,
            None,
        )

        if not callable(method):
            raise TypeError(
                "Invalid injected capability "
                f"{dependency_name!r}: "
                f"missing callable {method_name!r}"
            )