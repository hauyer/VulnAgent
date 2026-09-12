"""Replaceable ports for the controlled robustness engine."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .models import (
    EndpointSpec,
    InputFieldSpec,
    ProbeObservation,
    ProcessSnapshot,
    RobustnessCase,
    SandboxAttestation,
    SandboxPolicy,
)


class TestCaseGenerator(Protocol):
    def generate(
        self,
        base_request: dict[str, object],
        fields: Sequence[InputFieldSpec],
        policy: SandboxPolicy,
    ) -> list[RobustnessCase]: ...


class LocalServiceProbe(Protocol):
    async def execute(self, endpoint: EndpointSpec, case: RobustnessCase) -> ProbeObservation: ...


class ProcessMonitor(Protocol):
    async def snapshot(self) -> ProcessSnapshot: ...


class ResettableSandbox(Protocol):
    async def prepare(self, policy: SandboxPolicy) -> SandboxAttestation: ...
    async def reset(self) -> None: ...
