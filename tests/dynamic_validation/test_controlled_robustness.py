"""Safety and evidence tests for the local robustness engine."""

import pytest

from vulnagent.dynamic_validation import (
    ControlledRobustnessEngine,
    EndpointSpec,
    InputFieldSpec,
    ObservationKind,
    ProbeObservation,
    ProcessSnapshot,
    SandboxAttestation,
    robustness_evidence,
    validate_loopback_endpoint,
)


class FakeProbe:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, endpoint, case):
        self.calls += 1
        return ProbeObservation(
            status_code=None if self.calls == 1 else 400,
            duration_ms=10,
            timed_out=self.calls == 1,
        )


class FakeMonitor:
    async def snapshot(self):
        return ProcessSnapshot(running=True, memory_bytes=1024)


class FakeSandbox:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.prepared = False
        self.reset_count = 0

    async def prepare(self, policy):
        self.prepared = True
        return SandboxAttestation(
            low_privilege=self.valid,
            external_network_disabled=self.valid,
            read_only_root=self.valid,
            disposable=self.valid,
            sandbox_id="sandbox-test",
        )

    async def reset(self):
        self.reset_count += 1


def test_remote_endpoint_is_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        validate_loopback_endpoint(EndpointSpec(url="https://example.com/api"))


@pytest.mark.asyncio
async def test_engine_records_redacted_results_and_resets() -> None:
    sandbox = FakeSandbox()
    engine = ControlledRobustnessEngine(FakeProbe(), FakeMonitor(), sandbox)
    run = await engine.run(
        EndpointSpec(url="http://127.0.0.1:11434/api/generate"),
        {"prompt": "baseline"},
        [InputFieldSpec(path=("prompt",), value_type="string", max_length=32, nullable=True)],
    )

    assert sandbox.prepared is True
    assert sandbox.reset_count == 1
    assert run.reset_completed is True
    assert run.results[0].observation is ObservationKind.TIMEOUT
    record = run.public_record()
    assert record["raw_inputs_retained"] is False
    assert "request_body" not in str(record)
    evidence = robustness_evidence(task_id="task", finding_id="finding", run=run)
    assert evidence.data["finding_id"] == "finding"
    assert evidence.data["local_only"] is True


@pytest.mark.asyncio
async def test_invalid_sandbox_attestation_fails_closed_and_resets() -> None:
    sandbox = FakeSandbox(valid=False)
    engine = ControlledRobustnessEngine(FakeProbe(), FakeMonitor(), sandbox)
    with pytest.raises(PermissionError, match="attestation"):
        await engine.run(
            EndpointSpec(url="http://localhost:11434/api/generate"),
            {"prompt": "baseline"},
            [InputFieldSpec(path=("prompt",), value_type="string")],
        )
    assert sandbox.reset_count == 1
