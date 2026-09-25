"""V0.8 Dynamic Confirmation: harness generation and coverage tracking.

``HarnessGenerator`` writes an isolated runner script for a target so the
fuzz backend can execute candidates with a fresh interpreter per input;
``CoverageTracker`` records execution statistics across a run.
"""

from __future__ import annotations

from pathlib import Path

_HARNESS_TEMPLATE = '''\
"""VulnAgent generated harness: run TARGET with one input file."""
from __future__ import annotations

import sys
from pathlib import Path

_TARGET = {target!r}
_INPUT = {input_file!r}

with open(_INPUT, "rb") as stream:
    data = stream.read()

namespace = {{"__name__": "__main__", "__file__": str(_TARGET)}}
sys.argv = [_TARGET, data.decode(errors="replace").strip()]
sys.stdin = open(_INPUT, "r", encoding="utf-8")  # TextIOWrapper keeps .buffer
try:
    exec(compile(Path(_TARGET).read_text(encoding="utf-8"), str(_TARGET), "exec"), namespace)
except SystemExit:
    raise
'''


class HarnessGenerator:
    """Generate an isolated runner harness for a target script."""

    def generate(self, target: Path, input_file: Path, output: Path) -> Path:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            _HARNESS_TEMPLATE.format(target=str(target.resolve()), input_file=str(input_file.resolve())),
            encoding="utf-8",
        )
        return output


class CoverageTracker:
    """Execution statistics for a fuzz run."""

    def __init__(self) -> None:
        self.executions = 0
        self.timeouts = 0
        self.nonzero_exits = 0
        self.exceptions = 0
        self.unique_inputs = 0

    def record(self, *, input_sha: str | None = None, timed_out: bool = False,
               returncode: int | None = None, exception: bool = False) -> None:
        self.executions += 1
        if timed_out:
            self.timeouts += 1
        if returncode not in (None, 0):
            self.nonzero_exits += 1
        if exception:
            self.exceptions += 1

    def report(self) -> dict[str, int]:
        return {
            "executions": self.executions,
            "timeouts": self.timeouts,
            "nonzero_exits": self.nonzero_exits,
            "exceptions": self.exceptions,
        }
