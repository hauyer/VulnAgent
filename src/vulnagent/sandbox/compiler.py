"""Local C/C++ compilation sandbox for authorized dynamic targets.

The compiler sandbox locates a real clang-cl toolchain, builds a libFuzzer
target with AddressSanitizer and prepares the Windows ASan runtime next to
the executable. A missing or unusable toolchain is reported as ``not_run``
with an explicit reason — never as a successful build or as "zero findings".
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SANITIZER_FLAGS = ("-fsanitize=fuzzer,address",)

_LLVM_BIN_CANDIDATES = (
    Path(os.environ.get("VULNAGENT_CLANG_DIR", "")).expanduser(),
    Path("C:/Program Files/LLVM/bin"),
    Path("C:/Program Files (x86)/LLVM/bin"),
)

_ASAN_DLL_NAME = "clang_rt.asan_dynamic-x86_64.dll"


@dataclass(frozen=True, slots=True)
class CompileResult:
    """Honest outcome of one compiler-sandbox build."""

    compiled: bool
    binary_path: str | None = None
    engine_version: str | None = None
    compile_command_hash: str | None = None
    reason: str | None = None
    stderr: str = ""


def locate_clang() -> Path | None:
    """Return the clang executable path or ``None`` when unavailable.

    The GNU driver (``clang``) is used instead of ``clang-cl`` because the
    Windows ``clang-cl`` build links ASan without effective instrumentation
    (verified locally: heap/stack checks are silently disabled), while the
    GNU driver's ``-fsanitize=address`` works correctly.
    """

    # 1. Explicit environment override.
    env_path = os.environ.get("VULNAGENT_CLANG")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    # 2. Well-known install locations.
    for candidate in _LLVM_BIN_CANDIDATES:
        clang_exe = candidate / "clang.exe"
        if clang_exe.is_file():
            return clang_exe

    # 3. PATH lookup.
    found = shutil.which("clang")
    return Path(found) if found else None


def clang_version(clang: Path) -> str:
    """Read the clang version banner (engine_version fact)."""

    try:
        proc = subprocess.run(
            [str(clang), "--version"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        first = (proc.stdout or b"").decode(errors="replace").splitlines()
        if first:
            return first[0].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def compile_libfuzzer_target(
    source: Path,
    output_dir: Path,
    *,
    clang: Path | None = None,
    sanitizer: str = "address",
    opt_level: str = "-O0",
) -> CompileResult:
    """Compile a libFuzzer + sanitizer target for local authorized runs.

    ``-O0`` is the default on Windows: verified locally that ``-O1``
    optimizes away the instrumented stack accesses (ASan reports nothing
    for the same overflow at ``-O1``), while ``-O0`` detects them reliably.

    Returns ``CompileResult(compiled=False, reason=...)`` when the toolchain
    is missing, the source is invalid, or the build fails.
    """

    resolved_clang = clang or locate_clang()
    if resolved_clang is None:
        return CompileResult(
            compiled=False,
            reason="clang toolchain unavailable; set VULNAGENT_CLANG or install LLVM",
        )

    source = Path(source).resolve()
    if not source.is_file():
        return CompileResult(
            compiled=False,
            reason=f"source not found: {source}",
        )

    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    binary = output_dir / "target.exe"
    sanitizer_flag = f"-fsanitize=fuzzer,{sanitizer}"
    command = [
        str(resolved_clang),
        sanitizer_flag,
        opt_level,
        str(source),
        "-o",
        str(binary),
    ]

    command_hash = hashlib.sha256(
        " ".join(command).encode("utf-8")
    ).hexdigest()[:16]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CompileResult(
            compiled=False,
            reason=f"compiler launch failed: {exc}",
            engine_version=clang_version(resolved_clang),
        )

    if proc.returncode != 0 or not binary.is_file():
        return CompileResult(
            compiled=False,
            reason="clang build failed",
            engine_version=clang_version(resolved_clang),
            stderr=(proc.stderr or b"").decode(errors="replace")[:4096],
        )

    _stage_asan_runtime(binary.parent)

    return CompileResult(
        compiled=True,
        binary_path=str(binary),
        engine_version=clang_version(resolved_clang),
        compile_command_hash=command_hash,
    )


def _stage_asan_runtime(build_dir: Path) -> None:
    """Copy the Windows dynamic ASan runtime next to the executable.

    clang links ASan dynamically on Windows; the DLL must sit beside the
    binary or the process fails with STATUS_DLL_NOT_FOUND.
    """

    clang = locate_clang()
    if clang is None:
        return
    dll = clang.parent / _ASAN_DLL_NAME
    if not dll.is_file():
        # Fall back to the runtime directory shipped with the toolchain.
        alt = (
            clang.parent.parent
            / "lib"
            / "clang"
            / "23"
            / "lib"
            / "windows"
            / _ASAN_DLL_NAME
        )
        if alt.is_file():
            dll = alt
    if dll.is_file():
        shutil.copy2(dll, build_dir / dll.name)
