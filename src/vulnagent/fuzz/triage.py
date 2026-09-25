"""V0.8 Dynamic Confirmation: crash triage.

Classifies raw execution outcomes into crash records with sanitizer-style
labels (UBSan semantics: divide-by-zero, index-out-of-bounds, ...) extracted
from the target's traceback, plus deterministic crash evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256

from vulnagent.contracts import Evidence, EvidenceType

_EXCEPTION_PATTERN = re.compile(r"^(\w+Error|AssertionError|OverflowError|RecursionError|IndexError|ValueError)", re.MULTILINE)

# exception class -> UBSan-style semantic label
_UBSAN_LABELS = {
    "ZeroDivisionError": "ubsan.divide_by_zero",
    "IndexError": "ubsan.index_out_of_bounds",
    "OverflowError": "ubsan.integer_overflow",
    "UnicodeDecodeError": "ubsan.invalid_encoding",
    "ValueError": "ubsan.invalid_value",
    "RecursionError": "stack_exhaustion",
    "AssertionError": "assertion_failure",
    "MemoryError": "memory_exhaustion",
}


@dataclass(frozen=True, slots=True)
class CrashRecord:
    """One reproducible target crash."""

    crash_id: str
    input_bytes: bytes
    exit_code: int | None
    kind: str  # exception | timeout | nonzero
    exception_class: str | None
    sanitizer_label: str | None
    stderr_head: str
    task_id: str
    target_id: str

    def to_evidence(self, session_id: str, run_id: str) -> list[Evidence]:
        """CRASH_LOG + STACK_TRACE + FUZZ_INPUT evidence for verification."""
        crash = Evidence(
            evidence_id=f"{run_id}-crash-{self.crash_id}",
            task_id=self.task_id,
            evidence_type=EvidenceType.CRASH_LOG,
            source="PythonFuzzBackend",
            created_by="python-fuzz-backend",
            reliability=0.9,
            description=f"Crash {self.kind}: {self.exception_class or 'signal'} "
                        f"(exit={self.exit_code})",
            data={
                "kind": self.kind,
                "sanitizer_label": self.sanitizer_label,
                "exit_code": self.exit_code,
                "input": self.input_bytes.decode(errors="replace"),
                "stderr_head": self.stderr_head[:4000],
            },
        )
        stack = Evidence(
            evidence_id=f"{run_id}-stack-{self.crash_id}",
            task_id=self.task_id,
            evidence_type=EvidenceType.STACK_TRACE,
            source="PythonFuzzBackend",
            created_by="python-fuzz-backend",
            reliability=0.8,
            description=f"Traceback for crash {self.crash_id}",
            data={"traceback": self.stderr_head[:4000]},
        )
        trigger = Evidence(
            evidence_id=f"{run_id}-input-{self.crash_id}",
            task_id=self.task_id,
            evidence_type=EvidenceType.FUZZ_INPUT,
            source="PythonFuzzBackend",
            created_by="python-fuzz-backend",
            reliability=0.7,
            description=f"Reproducing input for crash {self.crash_id}",
            data={"input": self.input_bytes.decode(errors="replace")},
        )
        return [crash, stack, trigger]


class CrashTriage:
    """Classify an execution result into a CrashRecord."""

    def classify(
        self,
        *,
        execution,
        input_bytes: bytes,
        task_id: str,
        target_id: str,
        run_id: str,
        index: int,
    ) -> CrashRecord | None:
        """Return None when the execution was not a crash."""
        if execution.timed_out:
            return CrashRecord(
                crash_id=f"{index}",
                input_bytes=input_bytes,
                exit_code=None,
                kind="timeout",
                exception_class=None,
                sanitizer_label="timeout",
                stderr_head=execution.stderr.decode(errors="replace")[:4000],
                task_id=task_id,
                target_id=target_id,
            )
        if execution.returncode in (None, 0) and not execution.crashed:
            return None
        stderr = execution.stderr.decode(errors="replace")
        match = _EXCEPTION_PATTERN.search(stderr)
        exception_class = match.group(1) if match else None
        return CrashRecord(
            crash_id=f"{index}",
            input_bytes=input_bytes,
            exit_code=execution.returncode,
            kind="exception" if exception_class else "nonzero",
            exception_class=exception_class,
            sanitizer_label=_UBSAN_LABELS.get(exception_class or "", None),
            stderr_head=stderr[:4000],
            task_id=task_id,
            target_id=target_id,
        )
