"""S2: build the wasm3 (CVE-2021-38592) vulnerable + fixed ASan targets.

The project source lives in two detached worktrees of the vendored
``third_party/wasm3`` clone (the main checkout stays untouched):

* ``third_party/wasm3-vuln``  at ``5848808`` (8f3986a~1, the parent of the
  OSS-Fuzz #33554 fix, vulnerable to op_Const64 stack overflow)
* ``third_party/wasm3-fixed`` at ``8f3986a`` (the upstream fix commit,
  "Fix memory safety issues found by OSS-Fuzz (#301)")

Both worktrees carry a one-line build-time patch in
``source/m3_config_platforms.h`` so that clang on Windows does not apply the
32-byte-aligned ``vectorcall`` convention (which breaks the
``operations[4]`` array layout); the patch is documented in the case card and
changes no behavior on other toolchains.

Smoke: the vulnerable binary must produce an AddressSanitizer
heap-buffer-overflow on the trigger module with ``--stack-size 4096``; the
fixed binary must NOT (it traps with a controlled stack overflow instead).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

LLVM_CLANG = Path("C:/Program Files/LLVM/bin/clang.exe")
LLVM_ASAN_DLL = (
    Path("C:/Program Files/LLVM/lib/clang/23/lib/windows")
    / "clang_rt.asan_dynamic-x86_64.dll"
)

WASM3_VULN_REV = "5848808"          # 8f3986a~1 (parent of the fix)
WASM3_FIX_REV = "8f3986a"
WASM3_VULN_TREE = REPO_ROOT / "third_party" / "wasm3-vuln"
WASM3_FIXED_TREE = REPO_ROOT / "third_party" / "wasm3-fixed"
EXE_NAME = "wasm3_asan.exe"

_COMMON_FLAGS = [
    "-fsanitize=address",
    "-fno-omit-frame-pointer",
    "-g",
    "-O0",
    "-D_CRT_SECURE_NO_WARNINGS",
]


@dataclass(frozen=True)
class Wasm3BuildOutcome:
    status: str  # success / unavailable / error / timeout
    vuln_path: Path | None
    fixed_path: Path | None
    build_log: Path | None
    smoke: dict | None = None
    reason: str = ""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(cmd: list[str], cwd: Path, log: Path, timeout: int = 300) -> tuple[int, str]:
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, timeout=timeout, check=False
        )
        err = (proc.stderr or b"").decode(errors="replace")
        out = (proc.stdout or b"").decode(errors="replace")
        log.write_text(out + "\n" + err, encoding="utf-8")
        return proc.returncode, err
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.write_text(f"launch failed: {exc}", encoding="utf-8")
        return -1, str(exc)


def _build_one(tree: Path, out_dir: Path) -> tuple[bool, Path | None, Path, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "build.log"
    if not LLVM_CLANG.is_file():
        return False, None, log, "LLVM clang not found"
    if not (tree / "source" / "m3_compile.c").is_file():
        return False, None, log, f"wasm3 source tree missing: {tree}"
    cmd = [
        str(LLVM_CLANG),
        *_COMMON_FLAGS,
        "-I", str(tree / "source"),
        "-I", str(tree / "platforms" / "app"),
        *[str(p) for p in (tree / "source").glob("*.c")],
        str(tree / "platforms" / "app" / "main.c"),
        "-o", str(out_dir / EXE_NAME),
    ]
    rc, _ = _run(cmd, tree, log)
    if rc != 0:
        return False, None, log, f"compile failed (rc={rc}); see build.log"
    exe = out_dir / EXE_NAME
    if LLVM_ASAN_DLL.is_file():
        shutil.copy2(LLVM_ASAN_DLL, out_dir / LLVM_ASAN_DLL.name)
    return True, exe, log, ""


def _run_smoke(exe: Path, trigger: Path, log: Path) -> dict:
    env_asan = "detect_leaks=0"
    rc, err = _run(
        [str(exe), "--stack-size", "4096", str(trigger)],
        exe.parent,
        log,
        timeout=120,
    )
    return {
        "exit_code": rc,
        "asan_detected": "AddressSanitizer" in err,
        "heap_buffer_overflow": "heap-buffer-overflow" in err,
        "trap_stack_overflow": "stack overflow" in err,
    }


def build_wasm3_target(trigger_wasm: bytes, out_root: Path) -> Wasm3BuildOutcome:
    """Build both targets and smoke them against the trigger module."""
    out_root.mkdir(parents=True, exist_ok=True)
    build_dir = out_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    log_dir = build_dir
    (build_dir / "trigger.wasm").write_bytes(trigger_wasm)

    for label, tree in (("vuln", WASM3_VULN_TREE), ("fixed", WASM3_FIXED_TREE)):
        if not tree.is_dir():
            return Wasm3BuildOutcome(
                status="unavailable",
                vuln_path=None,
                fixed_path=None,
                build_log=None,
                reason=(
                    f"wasm3 worktree missing: {tree}. Create with:\n"
                    "  git -C third_party/wasm3 worktree add ../wasm3-vuln "
                    f"{WASM3_VULN_REV}\n"
                    "  git -C third_party/wasm3 worktree add ../wasm3-fixed "
                    f"{WASM3_FIX_REV}\n"
                    "and apply the vectorcall build patch documented in the "
                    "case card."
                ),
            )

    ok_v, exe_v, log_v, reason_v = _build_one(
        WASM3_VULN_TREE, build_dir / "vuln"
    )
    if not ok_v:
        return Wasm3BuildOutcome(
            status="error", vuln_path=None, fixed_path=None,
            build_log=log_v, reason=reason_v,
        )
    ok_f, exe_f, log_f, reason_f = _build_one(
        WASM3_FIXED_TREE, build_dir / "fixed"
    )
    if not ok_f:
        return Wasm3BuildOutcome(
            status="error", vuln_path=exe_v, fixed_path=None,
            build_log=log_f, reason=reason_f,
        )

    smoke_v = _run_smoke(exe_v, build_dir / "trigger.wasm", build_dir / "smoke_vuln.log")
    smoke_f = _run_smoke(exe_f, build_dir / "trigger.wasm", build_dir / "smoke_fixed.log")

    vuln_ok = bool(smoke_v["heap_buffer_overflow"])
    fixed_ok = not smoke_f["asan_detected"]
    status = "success" if (vuln_ok and fixed_ok) else "mismatch"

    return Wasm3BuildOutcome(
        status=status,
        vuln_path=exe_v,
        fixed_path=exe_f,
        build_log=log_v,
        smoke={
            "vulnerable": smoke_v,
            "fixed": smoke_f,
            "expectation": (
                "vulnerable: ASan heap-buffer-overflow; "
                "fixed: no ASan report (controlled trap)"
            ),
            "trigger_sha256": _sha256_file(build_dir / "trigger.wasm"),
            "vuln_target_sha256": _sha256_file(exe_v),
            "fixed_target_sha256": _sha256_file(exe_f),
        },
        reason=(
            f"vuln asan_overflow={vuln_ok} fixed asan_free={fixed_ok}"
        ),
    )


def write_wasm3_build_record(
    out_root: Path, trigger_wasm: bytes, *, case_id: str
) -> Wasm3BuildOutcome:
    outcome = build_wasm3_target(trigger_wasm, out_root)
    record = {
        "case_id": case_id,
        "upstream_url": "https://github.com/wasm3/wasm3",
        "vulnerable_revision": WASM3_VULN_REV,
        "fixed_revision": WASM3_FIX_REV,
        "vulnerable_tree": str(WASM3_VULN_TREE),
        "fixed_tree": str(WASM3_FIXED_TREE),
        "build_status": outcome.status,
        "build_patch": (
            "source/m3_config_platforms.h: vectorcall disabled for "
            "clang-on-Windows (aligned(32) breaks the operations[4] array); "
            "build-time only, both worktrees"
        ),
        "compiler": "LLVM clang -fsanitize=address -g -O0",
        "smoke": outcome.smoke,
        "reason": outcome.reason,
    }
    (out_root / "build.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return outcome
