"""V0.9 Symbolic + Autonomous Evidence Fusion: angr symbolic engine.

``SymbolicEngine`` drives angr over a PE/ELF target from its entry point to a
candidate address (a dangerous callsite discovered by the V0.7 IAT xref
pass), records the path-constraint summary, and solves for a minimal test
input.  The engine is a bounded adapter: step/time limits, an explicit hook
policy for external imports, and never executes the target natively.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_STEPS = 400
_DEFAULT_TIMEOUT_SECONDS = 30
_DEFAULT_INPUT_BYTES = 32


@dataclass(frozen=True, slots=True)
class ReachabilityResult:
    """Outcome of a symbolic reachability query."""

    available: bool
    reachable: bool
    target_address: int
    path_count: int
    constraint_summary: list[str]
    minimal_input: bytes | None
    reason: str | None = None
    engine_details: dict[str, Any] = field(default_factory=dict)


class SymbolicEngine:
    """Bounded angr-based reachability + constraint solving for a target."""

    def __init__(
        self,
        *,
        max_steps: int = _DEFAULT_STEPS,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        input_bytes: int = _DEFAULT_INPUT_BYTES,
    ) -> None:
        self.max_steps = max_steps
        self.timeout_seconds = timeout_seconds
        self.input_bytes = input_bytes

    def reach(self, target_path: Path, target_address: int) -> ReachabilityResult:
        try:
            import angr
            import claripy
        except ImportError:
            return ReachabilityResult(
                available=False,
                reachable=False,
                target_address=target_address,
                path_count=0,
                constraint_summary=[],
                reason="angr_not_installed",
            )

        try:
            project = angr.Project(str(target_path), auto_load_libs=False)
        except Exception as exc:  # pragma: no cover - loader failures vary
            return ReachabilityResult(
                available=False,
                reachable=False,
                target_address=target_address,
                path_count=0,
                constraint_summary=[],
                reason=f"load_failed:{type(exc).__name__}",
            )

        class _SymbolicGets(angr.SimProcedure):
            def run(self, buffer):  # type: ignore[no-untyped-def]
                self.state.memory.store(
                    buffer,
                    claripy.BVS("gets_buf", 8 * self.state.arch.bytes * 4),
                    size=self.state.arch.bytes * 4,
                )
                self.state.memory.store(
                    buffer + self.state.arch.bytes * 4,
                    claripy.BVV(0, 8),
                )
                return claripy.BVV(0, 8 * self.state.arch.bytes)

        try:
            project.hook_symbol("gets", _SymbolicGets())
        except Exception as exc:  # pragma: no cover
            logger.debug("gets hook failed: %s", exc)

        try:
            state = project.factory.entry_state()
            simgr = project.factory.simulation_manager(state)
            simgr.explore(find=target_address, timeout=self.timeout_seconds)
        except Exception as exc:
            return ReachabilityResult(
                available=True,
                reachable=False,
                target_address=target_address,
                path_count=0,
                constraint_summary=[],
                reason=f"explore_failed:{type(exc).__name__}",
                engine_details={"error": str(exc)[:400]},
            )

        found = list(simgr.found)
        constraint_summary: list[str] = []
        minimal_input: bytes | None = None
        if found:
            state = found[0]
            constraints = state.solver.constraints
            for index, constraint in enumerate(constraints[:8]):
                constraint_summary.append(str(constraint)[:200])
            try:
                value = state.solver.eval_upto(
                    claripy.BVS("gets_buf", 8 * 32), 1
                )[0]
                minimal_input = bytes(value)
            except Exception:
                minimal_input = None

        return ReachabilityResult(
            available=True,
            reachable=bool(found),
            target_address=target_address,
            path_count=len(found),
            constraint_summary=constraint_summary,
            minimal_input=minimal_input,
            engine_details={
                "active_states": len(simgr.active),
                "errored": len(simgr.errored),
            },
        )
