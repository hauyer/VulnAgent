"""Internal models for bounded local-service robustness validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CaseKind(str, Enum):
    NULL_VALUE = "null_value"
    EMPTY_TEXT = "empty_text"
    BOUNDARY_NUMBER = "boundary_number"
    OVERSIZED_TEXT = "oversized_text"
    MALFORMED_TYPE = "malformed_type"


class ObservationKind(str, Enum):
    NORMAL = "normal"
    CRASH = "crash"
    ABNORMAL_EXIT = "abnormal_exit"
    MEMORY_ERROR = "memory_error"
    TIMEOUT = "timeout"
    SERVICE_UNAVAILABLE = "service_unavailable"


@dataclass(frozen=True, slots=True)
class InputFieldSpec:
    """One API input location and its documented defensive boundaries."""

    path: tuple[str, ...]
    value_type: str
    minimum: int | float | None = None
    maximum: int | float | None = None
    max_length: int | None = None
    nullable: bool = False


@dataclass(frozen=True, slots=True)
class RobustnessCase:
    """Generated input retained only in memory for one bounded request."""

    case_id: str
    kind: CaseKind
    field_path: tuple[str, ...]
    request_body: dict[str, Any] = field(repr=False)
    input_summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """A local official API endpoint; remote targets are rejected by policy."""

    url: str
    method: str = "POST"
    timeout_seconds: float = 3.0
    max_response_bytes: int = 65_536


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Fail-closed requirements supplied to a resettable sandbox adapter."""

    low_privilege: bool = True
    external_network_disabled: bool = True
    read_only_root: bool = True
    disposable: bool = True
    memory_limit_mb: int = 512
    cpu_limit: float = 1.0
    process_limit: int = 32
    case_limit: int = 32
    max_text_length: int = 8_192

    def validate(self) -> None:
        if not all(
            (
                self.low_privilege,
                self.external_network_disabled,
                self.read_only_root,
                self.disposable,
            )
        ):
            raise ValueError("robustness validation requires a disposable low-privilege offline sandbox")
        if self.memory_limit_mb < 64 or self.cpu_limit <= 0 or self.process_limit < 1:
            raise ValueError("sandbox resource limits must be positive and bounded")
        if not 1 <= self.case_limit <= 128 or not 256 <= self.max_text_length <= 65_536:
            raise ValueError("case/text limits exceed the defensive validation bounds")


@dataclass(frozen=True, slots=True)
class SandboxAttestation:
    low_privilege: bool
    external_network_disabled: bool
    read_only_root: bool
    disposable: bool
    sandbox_id: str

    def satisfies(self, policy: SandboxPolicy) -> bool:
        return (
            (not policy.low_privilege or self.low_privilege)
            and (not policy.external_network_disabled or self.external_network_disabled)
            and (not policy.read_only_root or self.read_only_root)
            and (not policy.disposable or self.disposable)
        )


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    running: bool
    exit_code: int | None = None
    memory_bytes: int | None = None
    memory_error_detected: bool = False


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    status_code: int | None
    duration_ms: int
    timed_out: bool = False
    transport_error: str | None = None
    response_bytes: int = 0


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    case_kind: CaseKind
    field_path: tuple[str, ...]
    input_summary: dict[str, Any]
    observation: ObservationKind
    probe: ProbeObservation
    process_before: ProcessSnapshot
    process_after: ProcessSnapshot

    def public_record(self) -> dict[str, Any]:
        """Serialize metadata without raw request or response content."""

        return {
            "case_id": self.case_id,
            "case_kind": self.case_kind.value,
            "field_path": list(self.field_path),
            "input_summary": dict(self.input_summary),
            "observation": self.observation.value,
            "probe": asdict(self.probe),
            "process_before": asdict(self.process_before),
            "process_after": asdict(self.process_after),
        }


@dataclass(frozen=True, slots=True)
class RobustnessRun:
    endpoint: str
    sandbox_id: str
    results: tuple[CaseResult, ...]
    reset_completed: bool
    local_only: bool = True
    defensive_only: bool = True

    @property
    def anomaly_count(self) -> int:
        return sum(item.observation is not ObservationKind.NORMAL for item in self.results)

    def public_record(self) -> dict[str, Any]:
        return {
            "engine": "controlled-local-service-robustness",
            "endpoint": self.endpoint,
            "sandbox_id": self.sandbox_id,
            "local_only": self.local_only,
            "defensive_only": self.defensive_only,
            "reset_completed": self.reset_completed,
            "case_count": len(self.results),
            "anomaly_count": self.anomaly_count,
            "results": [item.public_record() for item in self.results],
            "raw_inputs_retained": False,
            "response_bodies_retained": False,
        }
