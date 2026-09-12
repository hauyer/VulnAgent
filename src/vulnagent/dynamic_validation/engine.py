"""Fail-closed orchestration for local defensive robustness checks."""

from __future__ import annotations

from collections.abc import Sequence

from .generator import BoundaryCaseGenerator
from .interfaces import LocalServiceProbe, ProcessMonitor, ResettableSandbox, TestCaseGenerator
from .models import (
    CaseResult,
    EndpointSpec,
    InputFieldSpec,
    ObservationKind,
    ProcessSnapshot,
    RobustnessRun,
    SandboxPolicy,
)
from .probe import validate_loopback_endpoint


class ControlledRobustnessEngine:
    """Run harmless API boundary cases and record only stability outcomes."""

    def __init__(
        self,
        probe: LocalServiceProbe,
        monitor: ProcessMonitor,
        sandbox: ResettableSandbox,
        generator: TestCaseGenerator | None = None,
    ) -> None:
        self.probe = probe
        self.monitor = monitor
        self.sandbox = sandbox
        self.generator = generator or BoundaryCaseGenerator()

    async def run(
        self,
        endpoint: EndpointSpec,
        base_request: dict[str, object],
        fields: Sequence[InputFieldSpec],
        policy: SandboxPolicy | None = None,
    ) -> RobustnessRun:
        selected_policy = policy or SandboxPolicy()
        selected_policy.validate()
        validate_loopback_endpoint(endpoint)
        attestation = await self.sandbox.prepare(selected_policy)
        if not attestation.satisfies(selected_policy):
            await self.sandbox.reset()
            raise PermissionError("sandbox attestation does not satisfy the defensive policy")
        results: list[CaseResult] = []
        reset_completed = False
        try:
            cases = self.generator.generate(base_request, fields, selected_policy)
            for case in cases:
                before = await self.monitor.snapshot()
                probe = await self.probe.execute(endpoint, case)
                after = await self.monitor.snapshot()
                results.append(
                    CaseResult(
                        case_id=case.case_id,
                        case_kind=case.kind,
                        field_path=case.field_path,
                        input_summary=case.input_summary,
                        observation=self._classify(before, probe, after),
                        probe=probe,
                        process_before=before,
                        process_after=after,
                    )
                )
        finally:
            await self.sandbox.reset()
            reset_completed = True
        return RobustnessRun(
            endpoint=endpoint.url,
            sandbox_id=attestation.sandbox_id,
            results=tuple(results),
            reset_completed=reset_completed,
        )

    @staticmethod
    def _classify(before, probe, after: ProcessSnapshot) -> ObservationKind:
        if after.memory_error_detected:
            return ObservationKind.MEMORY_ERROR
        if before.running and not after.running:
            return (
                ObservationKind.CRASH
                if after.exit_code not in {None, 0}
                else ObservationKind.ABNORMAL_EXIT
            )
        if probe.timed_out:
            return ObservationKind.TIMEOUT
        if probe.transport_error or probe.status_code is None or probe.status_code >= 500:
            return ObservationKind.SERVICE_UNAVAILABLE
        return ObservationKind.NORMAL
