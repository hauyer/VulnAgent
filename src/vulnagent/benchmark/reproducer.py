"""Reproduction comparator (L4, roadmap §2.1).

Compares a known vulnerable build against its fixed build on the same benign
input (replayed N times), recording exit codes, sanitizer signals and the
vulnerable-crashes / fixed-clean contrast.  It never crafts exploit payloads
and only runs already-authorized local targets.  The executor is injectable so
tests can drive it without launching processes.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

Runner = Callable[[Path, Path, Path, Sequence[str], int, int], tuple[int, str]]


def _default_runner(
    vulnerable_bin: Path,
    fixed_bin: Path,
    input_path: Path,
    args: Sequence[str],
    timeout: int,
    replay_count: int,
) -> tuple[int, str]:
    """Run both binaries on the same input; returns (vulnerable_exit, stderr)."""
    command = [str(vulnerable_bin), *args, str(input_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "timeout"


@dataclass(frozen=True, slots=True)
class ReproductionResult:
    vulnerable_bin: str
    fixed_bin: str
    input_sha256: str
    replay_count: int
    vulnerable_crashed: bool
    fixed_crashed: bool
    vulnerable_exit: int | None
    fixed_exit: int | None
    vulnerable_sanitizer: str | None
    fixed_sanitizer: str | None
    contrast_clean: bool  # vulnerable crashes while fixed does not
    note: str = ""


_SANITIZER_HINTS = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error")


def _sanitizer_from(stderr: str) -> str | None:
    for hint in _SANITIZER_HINTS:
        if hint.lower() in stderr.lower():
            return hint
    return None


class ReproductionComparator:
    """Deterministic vulnerable-vs-fixed contrast on one benign input."""

    def __init__(self, runner: Runner = _default_runner) -> None:
        self._runner = runner

    def compare(
        self,
        *,
        vulnerable_bin: Path,
        fixed_bin: Path,
        input_path: Path,
        args: Sequence[str] = (),
        replay_count: int = 3,
        timeout: int = 10,
    ) -> ReproductionResult:
        if replay_count < 1:
            raise ValueError("replay_count must be >= 1")
        vuln_crashed = 0
        fix_crashed = 0
        vuln_exits: list[int] = []
        fix_exits: list[int] = []
        vuln_stderr = ""
        fix_stderr = ""
        for _ in range(replay_count):
            vuln_exit, vuln_err = self._runner(
                vulnerable_bin, fixed_bin, input_path, args, timeout, replay_count
            )
            fix_exit, fix_err = self._runner(
                fixed_bin, vulnerable_bin, input_path, args, timeout, replay_count
            )
            vuln_exits.append(vuln_exit)
            fix_exits.append(fix_exit)
            vuln_stderr = vuln_err
            fix_stderr = fix_err
            if _is_crash(vuln_exit):
                vuln_crashed += 1
            if _is_crash(fix_exit):
                fix_crashed += 1
        return ReproductionResult(
            vulnerable_bin=str(vulnerable_bin),
            fixed_bin=str(fixed_bin),
            input_sha256=_sha256(input_path),
            replay_count=replay_count,
            vulnerable_crashed=vuln_crashed == replay_count,
            fixed_crashed=fix_crashed == replay_count,
            vulnerable_exit=_mode(vuln_exits),
            fixed_exit=_mode(fix_exits),
            vulnerable_sanitizer=_sanitizer_from(vuln_stderr),
            fixed_sanitizer=_sanitizer_from(fix_stderr),
            contrast_clean=(
                vuln_crashed == replay_count and fix_crashed == 0
            ),
            note=(
                "vulnerable crashes every replay, fixed build is clean"
                if vuln_crashed == replay_count and fix_crashed == 0
                else "no clean contrast observed"
            ),
        )


def _is_crash(exit_code: int) -> bool:
    if exit_code is None:
        return False
    if exit_code < 0:  # negative => signal / exception (e.g. Windows -1073741819)
        return True
    # ASan/UBSan abort typically yields exit code 1; treat any nonzero as a
    # diagnostic exit so sanitizer reports are not silently dropped.
    return exit_code != 0


def _mode(values: list[int]) -> int | None:
    if not values:
        return None
    return max(set(values), key=values.count)


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
