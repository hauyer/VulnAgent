"""Provider-neutral application dependency definitions.

This module groups public capability Protocol implementations required
by the VulnAgent composition root.

No concrete analyzer, fuzzer, verifier, report generator or external
provider implementation may be imported here.
"""

from dataclasses import dataclass
from inspect import iscoroutinefunction
from typing import Any

from vulnagent.contracts import (
    BinaryAnalyzer,
    BinaryFeatureAnalyzer,
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
    binary_logic_analyzer: BinaryFeatureAnalyzer
    binary_obfuscation_analyzer: BinaryFeatureAnalyzer

    fuzz_engine: FuzzEngine

    verifier: VulnerabilityVerifier

    report_generator: ReportGenerator

    # V0.5 protected-program capabilities are optional so existing embedders
    # can retain the frozen V0.4 bundle while the composition root enables them.
    program_restorer: Any | None = None
    code_deobfuscator: Any | None = None
    code_audit_enabled: bool = False

    def __post_init__(self) -> None:
        """Fail fast when an injected capability is structurally invalid.

        VulnAgent capability Protocol methods are asynchronous.

        Merely checking ``callable()`` is insufficient because a
        synchronous implementation would pass bootstrap validation and
        fail only later when an Agent tries to ``await`` it.

        Therefore every required operation is checked both for
        callability and coroutine-function semantics.
        """

        self._require_async_callable(
            self.source_parser,
            "analyze",
            "source_parser",
        )

        self._require_async_callable(
            self.source_auditor,
            "audit",
            "source_auditor",
        )

        self._require_async_callable(
            self.binary_analyzer,
            "analyze",
            "binary_analyzer",
        )

        self._require_async_callable(
            self.binary_logic_analyzer,
            "inspect",
            "binary_logic_analyzer",
        )

        self._require_async_callable(
            self.binary_obfuscation_analyzer,
            "inspect",
            "binary_obfuscation_analyzer",
        )

        self._require_async_callable(
            self.fuzz_engine,
            "run",
            "fuzz_engine",
        )

        self._require_async_callable(
            self.verifier,
            "verify",
            "verifier",
        )

        self._require_async_callable(
            self.report_generator,
            "generate",
            "report_generator",
        )

        if self.program_restorer is not None:
            self._require_async_callable(
                self.program_restorer,
                "restore",
                "program_restorer",
            )

        if self.code_deobfuscator is not None:
            self._require_async_callable(
                self.code_deobfuscator,
                "restore",
                "code_deobfuscator",
            )

    @staticmethod
    def _require_async_callable(
        dependency: Any,
        method_name: str,
        dependency_name: str,
    ) -> None:
        """Validate one asynchronous capability operation.

        Raises:
            TypeError:
                If the dependency does not expose the required callable
                method or if the method is not asynchronous.
        """

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

        if not iscoroutinefunction(method):
            raise TypeError(
                "Invalid injected capability "
                f"{dependency_name!r}: "
                f"method {method_name!r} must be async"
            )
