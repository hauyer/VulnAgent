"""S1: de-identified discovery ports for blind benchmark runs.

The blind discovery protocol keeps every answer artifact (CVE id, patch
commit, function names, trigger payloads, the ground-truth directory) on the
evaluator side.  The types in this module are the only interface between the
external experiment scheduler and the agent-visible discovery process:

* ``AgentTargetSpec``      - de-identified facts a discovery run may know.
* ``ExecutionObservation`` - facts observed from one target execution; never
  a conclusion about the root cause.
* ``BoundedTargetExecutor``- runs one input against the target under enforced
  resource limits and reports what it observed, plus which isolation controls
  were actually enforced (never policy intent).
* ``DiscoveryPolicy``      - proposes raw inputs; carries no label knowledge.

Triage of observations into candidates must stay target-agnostic: an abnormal
exit is recorded as a fault observation; ``cwe_id`` and ``location`` are only
filled when the observation itself (sanitizer output, symbolized stack frames)
supports them, otherwise they stay ``None`` / empty.
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from vulnagent.sandbox import SandboxManager, SandboxPolicy

_SEH_ACCESS_VIOLATION = 0xC0000005
_ASAN_FAILFAST = 0xC0000409  # Windows ASan termination code

_SANITIZER_PATTERNS = (
    (re.compile(r"AddressSanitizer", re.I), "address"),
    (re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.I), "undefined"),
    (re.compile(r"LeakSanitizer", re.I), "leak"),
    (re.compile(r"MemorySanitizer", re.I), "memory"),
    (re.compile(r"ThreadSanitizer", re.I), "thread"),
)

_STACK_FRAME_PATTERNS = (
    # ASan style:  #0 0x7ff6... in js_build_for_in_iterator quickjs.c:1234:5
    re.compile(r"in\s+([^\s]+)\s+([^\s]+):(\d+)"),
    # ASan style:  #1 0x... in func /path/file.c:56
    re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.+):(\d+)"),
    # Symbolizer style:  function at file:line
    re.compile(r"at\s+([^\s]+):(\d+)"),
)

# Windows ASan report style:  #0 0x7ff6503055d8 (C:\...\wasm3_asan.exe+0x155d8)
_PE_FRAME_PATTERN = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+\(\S*(?:\\|/)([^\\/)]+)\.exe\+0x([0-9a-fA-F]+)\)"
)
_DEFAULT_PE_IMAGE_BASE = 0x140000000  # clang x64 PE default


def _pe_image_base(exe_path: Path) -> int:
    """Read OptionalHeader.ImageBase from a PE32+/PE32 binary (pure struct)."""
    try:
        data = exe_path.read_bytes()
        if data[:2] != b"MZ":
            return _DEFAULT_PE_IMAGE_BASE
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return _DEFAULT_PE_IMAGE_BASE
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        if magic == 0x20B:  # PE32+
            return struct.unpack_from("<Q", data, e_lfanew + 48)[0]
        if magic == 0x10B:  # PE32
            return struct.unpack_from("<I", data, e_lfanew + 52)[0]
    except (OSError, struct.error):
        pass
    return _DEFAULT_PE_IMAGE_BASE


def symbolize_asan_frames(stderr: str, exe_path: Path) -> tuple[str, ...]:
    """Resolve Windows ASan ``(exe+0xRVA)`` frames to ``file:line``.

    This is ordinary crash-report symbolization (the addr2line equivalent) done
    by the harness tooling; resolved frames are raw observations about where
    the crash stack points, never a conclusion about the root cause.  Frame
    paths are reduced to the target-relative basename so the evaluator can
    grade them against the ground-truth location.
    """
    if not exe_path.is_file():
        return ()
    symbolizer = Path("C:/Program Files/LLVM/bin/llvm-symbolizer.exe")
    if not symbolizer.is_file():
        return ()
    base = _pe_image_base(exe_path)
    addrs: list[str] = []
    for line in stderr.splitlines():
        m = _PE_FRAME_PATTERN.search(line)
        if m:
            addrs.append(hex(base + int(m.group(2), 16)))
    if not addrs:
        return ()
    try:
        proc = subprocess.run(
            [str(symbolizer), "-e", str(exe_path), "-f", "-p", *addrs],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    frames: list[str] = []
    for out_line in (proc.stdout or b"").decode(errors="replace").splitlines():
        # llvm-symbolizer -f -p prints "func at path:line:col" or "path:line".
        m = re.search(r"at\s+(\S+?):(\d+)(?::\d+)?\s*$", out_line)
        if not m:
            continue
        path = m.group(1).strip().replace("\\", "/")
        if path in {"??", "<null>"} or path.startswith("("):
            continue
        frame = f"{Path(path).name}:{m.group(2)}"
        if frame not in frames:
            frames.append(frame)
    return tuple(frames)


def _is_crash_exit(code: int | None) -> bool:
    """NT exception exit codes (>= 0xC0000000) mark a crash on Windows."""
    return code is not None and code >= 0xC0000000


@dataclass(frozen=True)
class AgentTargetSpec:
    """Everything the discovery process is allowed to know about a target.

    ``opaque_case_id`` is a neutral identifier; it must never carry a CVE id,
    CWE id, patch commit or any answer-derived phrase.
    """

    opaque_case_id: str
    target_path: Path
    target_sha256: str | None
    seed_dir: Path
    time_budget_seconds: int
    max_executions: int
    per_input_timeout_seconds: float = 30.0
    memory_limit_mb: int | None = None
    max_output_bytes: int = 64 * 1024
    exec_args: tuple[str, ...] = field(default_factory=tuple)
    symbolize_frames: bool = False


@dataclass(frozen=True)
class ExecutionObservation:
    """Observed outcome of one input against the target.

    ``sanitizer_kind`` / ``stack_frames`` / ``stderr_head`` are raw
    observations.  ``location``-style conclusions are NOT made here; the
    triage layer derives candidate facts from these fields only.
    """

    input_sha256: str
    target_sha256: str
    exit_code: int | None
    timed_out: bool
    crashed: bool
    sanitizer_kind: str | None
    stack_frames: tuple[str, ...]
    stderr_artifact: Path | None
    isolation_capabilities: frozenset[str]
    stderr_head: str = ""
    error: str | None = None

    @property
    def crash_code_kind(self) -> str | None:
        """Human-readable fault kind from the exit code, if one exists."""
        if self.exit_code is None:
            return None
        if self.exit_code == _SEH_ACCESS_VIOLATION:
            return "SEH access violation"
        if _is_crash_exit(self.exit_code):
            return f"NT exception exit 0x{self.exit_code:08X}"
        return None


class BoundedTargetExecutor(Protocol):
    """Run one input under enforced limits and report only observations."""

    def execute(self, spec: AgentTargetSpec, input_path: Path) -> ExecutionObservation: ...

    def capabilities(self) -> frozenset[str]:
        """Isolation controls actually enforced by the backend."""
        ...


class DiscoveryPolicy(Protocol):
    """Propose raw input bytes; must carry no label knowledge."""

    def propose_inputs(self, spec: AgentTargetSpec, *, seed: int) -> list[bytes]: ...


def parse_sanitizer_kind(stderr: str) -> str | None:
    """Detect which sanitizer reported, from raw stderr text."""
    for pattern, kind in _SANITIZER_PATTERNS:
        if pattern.search(stderr):
            return kind
    return None


def parse_stack_frames(stderr: str, *, max_frames: int = 8) -> tuple[str, ...]:
    """Extract ``file:line``-bearing frames from raw sanitizer/stack output.

    Only frames that carry a concrete file and line are kept; a frame without
    a location cannot be turned into a candidate location.
    """
    frames: list[str] = []
    for line in stderr.splitlines():
        for pattern in _STACK_FRAME_PATTERNS:
            m = pattern.search(line)
            if m is None:
                continue
            if pattern.groups == 2:
                path, line_no = m.group(1), m.group(2)
            else:
                _func, path, line_no = m.group(1), m.group(2), m.group(3)
            path = path.strip().replace("\\", "/")
            if path.startswith("(") or path in {"<null>", "??"}:
                continue
            frame = f"{path}:{line_no}"
            if frame not in frames:
                frames.append(frame)
            break
        if len(frames) >= max_frames:
            break
    return tuple(frames)


class SandboxBoundedExecutor:
    """Concrete executor delegating to the existing ``SandboxManager``.

    The sandbox backends enforce process-tree / CPU / memory limits on
    Windows via a Job Object and explicitly report network and filesystem
    isolation as unsupported; those facts are surfaced verbatim in
    ``isolation_capabilities`` so a report can never mistake intent for an
    enforced control.
    """

    def __init__(self, max_output_bytes: int = 64 * 1024) -> None:
        self.max_output_bytes = max_output_bytes

    def capabilities(self) -> frozenset[str]:
        # Static capability facts of the backend family actually used.
        return frozenset(
            {"process_tree_limits", "cpu_time_limits", "memory_limits"}
        )

    def execute(
        self, spec: AgentTargetSpec, input_path: Path
    ) -> ExecutionObservation:
        input_bytes = input_path.read_bytes()
        input_sha = hashlib.sha256(input_bytes).hexdigest()
        target_sha = (
            hashlib.sha256(Path(spec.target_path).read_bytes()).hexdigest()
            if Path(spec.target_path).is_file()
            else ""
        )
        if spec.target_sha256 and target_sha != spec.target_sha256:
            return ExecutionObservation(
                input_sha256=input_sha,
                target_sha256=target_sha,
                exit_code=None,
                timed_out=False,
                crashed=False,
                sanitizer_kind=None,
                stack_frames=(),
                stderr_artifact=None,
                isolation_capabilities=self.capabilities(),
                error="target hash mismatch; execution blocked",
            )

        policy = SandboxPolicy(
            timeout_ms=int(spec.per_input_timeout_seconds * 1000),
            collect_runtime_trace=True,
            max_processes=4,
            memory_limit_mb=spec.memory_limit_mb,
            cpu_time_ms=max(
                100, int(spec.per_input_timeout_seconds * 1000)
            ),
            network_enabled=False,
        )
        manager = SandboxManager(policy=policy)
        result = manager.execute(
            command=[str(spec.target_path), *spec.exec_args, str(input_path)],
            work_dir=Path(spec.target_path).parent,
            input_data=input_bytes,
        )

        enforced: object = result.metadata.get("enforced_controls", ())
        if isinstance(enforced, (list, tuple, set, frozenset)):
            capabilities = frozenset(str(item) for item in enforced)
        else:
            capabilities = self.capabilities()

        stderr = (result.stderr or "")[: self.max_output_bytes]
        stderr_artifact = None
        if stderr.strip():
            artifact_dir = input_path.parent
            stderr_artifact = artifact_dir / f"{input_path.name}.stderr.txt"
            try:
                stderr_artifact.write_text(stderr, encoding="utf-8")
            except OSError:
                stderr_artifact = None

        frames = list(parse_stack_frames(stderr))
        if spec.symbolize_frames:
            symbolized = symbolize_asan_frames(stderr, Path(spec.target_path))
            frames = [f for f in symbolized if f not in frames] + frames

        return ExecutionObservation(
            input_sha256=input_sha,
            target_sha256=target_sha,
            exit_code=result.return_code,
            timed_out=result.timed_out,
            crashed=result.crashed or _is_crash_exit(result.return_code),
            sanitizer_kind=parse_sanitizer_kind(stderr),
            stack_frames=tuple(frames),
            stderr_artifact=stderr_artifact,
            isolation_capabilities=capabilities,
            stderr_head=stderr[:2000],
            error=result.error,
        )


@dataclass(frozen=True)
class RootCauseCluster:
    """A group of observations sharing one root-cause key (triage fact)."""

    cluster_id: str
    key: str
    crash_code_kind: str | None
    sanitizer_kind: str | None
    top_frame: str | None
    observation_hashes: tuple[str, ...] = field(default_factory=tuple)


class ObservationTriage:
    """Target-agnostic triage: observations -> root-cause clusters.

    The clustering key uses only observed facts (crash kind, sanitizer kind,
    top stack frame); it never consults ground truth, case cards or labels.
    """

    @staticmethod
    def root_cause_key(obs: ExecutionObservation) -> str:
        parts = [
            obs.crash_code_kind or "no_crash",
            obs.sanitizer_kind or "no_sanitizer",
            obs.stack_frames[0] if obs.stack_frames else "no_frame",
        ]
        return "|".join(parts)

    @classmethod
    def cluster(
        cls, observations: list[ExecutionObservation], *, run_id: str
    ) -> list[RootCauseCluster]:
        grouped: dict[str, list[ExecutionObservation]] = {}
        for obs in observations:
            if not obs.crashed:
                continue
            grouped.setdefault(cls.root_cause_key(obs), []).append(obs)
        clusters: list[RootCauseCluster] = []
        for idx, key in enumerate(sorted(grouped)):
            members = grouped[key]
            first = members[0]
            clusters.append(
                RootCauseCluster(
                    cluster_id=f"{run_id}-cluster-{idx:04d}",
                    key=key,
                    crash_code_kind=first.crash_code_kind,
                    sanitizer_kind=first.sanitizer_kind,
                    top_frame=first.stack_frames[0]
                    if first.stack_frames
                    else None,
                    observation_hashes=tuple(
                        sorted(obs.input_sha256 for obs in members)
                    ),
                )
            )
        return clusters


__all__ = [
    "AgentTargetSpec",
    "ExecutionObservation",
    "BoundedTargetExecutor",
    "DiscoveryPolicy",
    "SandboxBoundedExecutor",
    "RootCauseCluster",
    "ObservationTriage",
    "parse_sanitizer_kind",
    "parse_stack_frames",
    "symbolize_asan_frames",
]
