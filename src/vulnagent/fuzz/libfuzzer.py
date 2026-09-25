"""Real libFuzzer + sanitizer engine (WP4 dynamic evidence).

Runs an already-compiled libFuzzer target under AddressSanitizer inside the
sandbox, parses the real fuzzer output, deduplicates crashes, replays crash
inputs independently, and contrasts the same input against the paired fixed
build. Every run records the development-guide 8.4 fields
(``compile_command_hash``, ``engine_version``, ``seed``, ``corpus_hash``,
``runs``, ``coverage``, ``crash_input_sha256``, ``sanitizer_kind``,
``stack_hash``, ``replay_count``, ``fixed_outcome``).

A missing target or toolchain is reported as ``not_run`` with an explicit
reason — never as zero findings.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    FuzzEngine,
    FuzzRequest,
    FuzzResult,
)
from vulnagent.sandbox import SandboxManager
from vulnagent.utils.ids import new_evidence_id

_ASAN_PATTERN = re.compile(r"ERROR: AddressSanitizer:\s*([a-z\-]+)", re.IGNORECASE)
_ARTIFACT_PATTERN = re.compile(r"Test unit written to\s+(\S+)", re.IGNORECASE)
_RUNS_PATTERN = re.compile(r"#(\d+)\s+(INITED|DONE|REDUCE|pulse)", re.IGNORECASE)
_COV_PATTERN = re.compile(r"cov:\s*(\d+)", re.IGNORECASE)
_CORP_PATTERN = re.compile(r"corp:\s*(\d+)/(\d+)b", re.IGNORECASE)
# Windows ASan frames look like "#0 0x7ff... (D:\...\target.exe+0x2b597)";
# POSIX frames include "in function". Extract a stable frame token either way.
_STACK_FRAME_PATTERN = re.compile(
    r"#\d+\s+0x[0-9a-f]+\s+(?:in\s+(\S+)|\(([^)]+)\))",
    re.IGNORECASE,
)
_TIMEOUT_PATTERN = re.compile(r"ERROR: libFuzzer: timeout", re.IGNORECASE)
_OOM_PATTERN = re.compile(r"ERROR: libFuzzer: out-of-memory|AddressSanitizer: out-of-memory", re.IGNORECASE)


@dataclass(slots=True)
class LibFuzzerRunStats:
    """Structured facts parsed from one real libFuzzer run."""

    done: bool = False
    runs: int = 0
    coverage: int = 0
    corpus_entries: int = 0
    corpus_bytes: int = 0
    sanitizer_kind: str | None = None
    crash_signature: str | None = None
    stack_hash: str | None = None
    artifact_path: str | None = None
    timed_out: bool = False
    oom: bool = False
    error: str | None = None

    @property
    def crashed(self) -> bool:
        return self.sanitizer_kind is not None and self.artifact_path is not None


def parse_libfuzzer_output(
    stdout: str,
    stderr: str,
) -> LibFuzzerRunStats:
    """Parse libFuzzer console output into structured, honest facts."""

    text = (stdout or "") + "\n" + (stderr or "")
    stats = LibFuzzerRunStats()

    for match in _RUNS_PATTERN.finditer(text):
        stats.runs = max(stats.runs, int(match.group(1)))
        if match.group(2) == "DONE":
            stats.done = True

    for cov_match in _COV_PATTERN.finditer(text):
        stats.coverage = max(stats.coverage, int(cov_match.group(1)))

    for corp_match in _CORP_PATTERN.finditer(text):
        stats.corpus_entries = max(stats.corpus_entries, int(corp_match.group(1)))
        stats.corpus_bytes = max(stats.corpus_bytes, int(corp_match.group(2)))

    artifact_match = _ARTIFACT_PATTERN.search(text)
    if artifact_match:
        stats.artifact_path = artifact_match.group(1)

    asan_match = _ASAN_PATTERN.search(text)
    if asan_match:
        stats.sanitizer_kind = asan_match.group(1)

    if _TIMEOUT_PATTERN.search(text):
        stats.timed_out = True

    if _OOM_PATTERN.search(text):
        stats.oom = True

    if asan_match:
        frames = [
            (match.group(1) or match.group(2))
            for match in _STACK_FRAME_PATTERN.finditer(stderr or "")
        ][:12]
        stats.crash_signature = asan_match.group(1)
        if frames:
            stats.stack_hash = hashlib.sha256(
                "\n".join(frames).encode("utf-8")
            ).hexdigest()[:16]

    if not stats.done and not stats.crashed and not stats.timed_out and not stats.oom:
        if "ERROR:" in text:
            stats.error = text.split("ERROR:")[-1].strip().splitlines()[0][:300]

    return stats


class RealLibFuzzerEngine(FuzzEngine):
    """Authorization-gated real libFuzzer/ASan engine behind the sandbox."""

    def __init__(
        self,
        sandbox: SandboxManager | None = None,
    ) -> None:
        self.sandbox = sandbox or SandboxManager()

    async def run(self, request: FuzzRequest) -> FuzzResult:
        # -------------------------------------------------
        # 1. Authorization gate
        # -------------------------------------------------
        if not request.authorized:
            return FuzzResult(
                task_id=request.task_id,
                target_id=request.target_id,
                executed=False,
                crashes=0,
                metadata={"reason": "target_not_authorized"},
            )

        # -------------------------------------------------
        # 2. Compiled-target validation
        # -------------------------------------------------
        binary = Path(request.target_path).resolve()
        if not binary.is_file():
            return FuzzResult(
                task_id=request.task_id,
                target_id=request.target_id,
                executed=False,
                crashes=0,
                metadata={
                    "reason": "compiled_target_not_found",
                    "target_path": str(binary),
                },
            )

        # -------------------------------------------------
        # 3. Run budget from request / metadata
        # -------------------------------------------------
        runs = int(request.metadata.get("runs", 0) or 0)
        max_len = int(request.metadata.get("max_len", 0) or 0)
        max_total_time = int(request.metadata.get("max_total_time", 0) or 0)
        seed_value = int(request.metadata.get("seed", 0) or 0)
        work_dir = Path(request.metadata.get("work_dir", binary.parent)).resolve()
        artifact_dir = Path(request.metadata.get("artifact_dir", work_dir / "artifacts"))
        fix_binary_value = request.metadata.get("fix_binary")
        compile_hash = request.metadata.get("compile_command_hash")
        engine_version = request.metadata.get("engine_version")

        work_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)

        corpus_hash = self._corpus_hash(request)

        fuzz_command = [
            str(binary),
            f"-seed={seed_value}",
            f"-artifact_prefix={artifact_dir}{os.sep}",
            "-timeout=5",
        ]
        if runs > 0:
            fuzz_command.append(f"-runs={runs}")
        if max_len > 0:
            fuzz_command.append(f"-max_len={max_len}")
        if max_total_time > 0:
            fuzz_command.append(f"-max_total_time={max_total_time}")

        seed_dir_value = request.metadata.get("seed_dir")
        if seed_dir_value:
            seed_dir = Path(str(seed_dir_value)).resolve()
            if seed_dir.is_dir():
                # Copy seeds into an isolated corpus dir: libFuzzer writes new
                # inputs back into the corpus dir, which must never mutate the
                # checked-in seed set.
                corpus_dir = work_dir / "corpus"
                corpus_dir.mkdir(parents=True, exist_ok=True)
                for path in sorted(seed_dir.iterdir()):
                    if path.is_file():
                        shutil.copy2(path, corpus_dir / path.name)
                fuzz_command.append(str(corpus_dir))

        sandbox_result = self.sandbox.execute(
            fuzz_command,
            work_dir=work_dir,
        )
        stats = parse_libfuzzer_output(
            sandbox_result.stdout,
            sandbox_result.stderr,
        )

        evidence: list[Evidence] = []
        metadata: dict = {
            "engine": "libfuzzer",
            "engine_version": engine_version,
            "compile_command_hash": compile_hash,
            "seed": seed_value,
            "corpus_hash": corpus_hash,
            "runs": stats.runs,
            "coverage": stats.coverage,
            "corpus_entries": stats.corpus_entries,
            "corpus_bytes": stats.corpus_bytes,
            "sanitizer_kind": stats.sanitizer_kind,
            "crash_signature": stats.crash_signature,
            "stack_hash": stats.stack_hash,
            "timed_out": stats.timed_out,
            "oom": stats.oom,
            "executed": sandbox_result.executed,
            "returncode": sandbox_result.return_code,
            "sandbox_error": sandbox_result.error,
        }

        # -------------------------------------------------
        # 4. Crash handling: artifact, replay, fixed contrast
        # -------------------------------------------------
        crash_input_sha256: str | None = None
        replay_count = 0
        fixed_outcome: str | None = None

        if stats.crashed:
            # The path printed by libFuzzer can be mangled by the Windows
            # console decoding of non-ASCII directories, so fall back to
            # scanning the artifact dir for crash-* files (most recent).
            artifact: Path | None = None
            if stats.artifact_path:
                candidate = Path(stats.artifact_path)
                if candidate.is_file():
                    artifact = candidate
            if artifact is None:
                candidates = sorted(
                    artifact_dir.glob("crash-*"),
                    key=lambda p: p.stat().st_mtime,
                )
                if candidates:
                    artifact = candidates[-1]

            if artifact is not None:
                crash_bytes = artifact.read_bytes()
                crash_input_sha256 = hashlib.sha256(crash_bytes).hexdigest()

                # Independent replay on the vulnerable binary.
                replay = self.sandbox.execute(
                    [str(binary), str(artifact)],
                    work_dir=work_dir,
                )
                replay_count = 1
                replay_stats = parse_libfuzzer_output(
                    replay.stdout,
                    replay.stderr,
                )
                replay_crashed = replay_stats.crashed

                # Fixed-version contrast with the same crash input.
                if fix_binary_value:
                    fix_binary = Path(str(fix_binary_value)).resolve()
                    if fix_binary.is_file():
                        fixed = self.sandbox.execute(
                            [str(fix_binary), str(artifact)],
                            work_dir=work_dir,
                        )
                        fixed_stats = parse_libfuzzer_output(
                            fixed.stdout,
                            fixed.stderr,
                        )
                        if fixed_stats.crashed:
                            fixed_outcome = "still_crashes"
                        elif fixed.return_code == 0:
                            fixed_outcome = "clean"
                        else:
                            fixed_outcome = f"nonzero_exit_{fixed.return_code}"
                    else:
                        fixed_outcome = "fix_binary_missing"
                else:
                    fixed_outcome = "no_fix_binary"
            else:
                metadata["artifact_read_error"] = str(artifact)

        metadata.update(
            {
                "crash_input_sha256": crash_input_sha256,
                "replay_count": replay_count,
                "fixed_outcome": fixed_outcome,
            }
        )

        # -------------------------------------------------
        # 5. Evidence
        # -------------------------------------------------
        evidence.append(
            Evidence(
                evidence_id=new_evidence_id(),
                task_id=request.task_id,
                evidence_type=EvidenceType.TOOL_RESULT,
                source="real_libfuzzer_engine",
                description="Real libFuzzer run summary under the sandbox.",
                data={
                    "engine_version": engine_version,
                    "compile_command_hash": compile_hash,
                    "runs": stats.runs,
                    "coverage": stats.coverage,
                    "corpus_hash": corpus_hash,
                    "executed": sandbox_result.executed,
                    "returncode": sandbox_result.return_code,
                    "timed_out": stats.timed_out,
                    "oom": stats.oom,
                    "stdout": (sandbox_result.stdout or "")[:2048],
                    "stderr": (sandbox_result.stderr or "")[:4096],
                },
                reliability=0.95,
                created_by="libfuzzer",
            )
        )

        if stats.crashed and crash_input_sha256:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=request.task_id,
                    evidence_type=EvidenceType.CRASH_LOG,
                    source="real_libfuzzer_engine",
                    description="Real sanitizer crash with replay and fixed contrast.",
                    data={
                        "sanitizer_kind": stats.sanitizer_kind,
                        "crash_signature": stats.crash_signature,
                        "stack_hash": stats.stack_hash,
                        "crash_input_sha256": crash_input_sha256,
                        "replay_count": replay_count,
                        "fixed_outcome": fixed_outcome,
                        "artifact_path": stats.artifact_path,
                        "stderr": (sandbox_result.stderr or "")[:8192],
                    },
                    reliability=0.95,
                    created_by="libfuzzer",
                )
            )

        return FuzzResult(
            task_id=request.task_id,
            target_id=request.target_id,
            executed=bool(sandbox_result.executed),
            crashes=1 if (stats.crashed and crash_input_sha256) else 0,
            coverage=float(stats.coverage) if stats.coverage > 0 else None,
            evidence=evidence,
            metadata=metadata,
        )

    @staticmethod
    def _corpus_hash(request: FuzzRequest) -> str:
        """Hash the seed corpus content (files only, deterministic order)."""

        seed_dir_value = request.metadata.get("seed_dir")
        if not seed_dir_value:
            return hashlib.sha256(b"empty").hexdigest()
        seed_dir = Path(str(seed_dir_value)).resolve()
        if not seed_dir.is_dir():
            return hashlib.sha256(b"empty").hexdigest()

        digest = hashlib.sha256()
        for path in sorted(seed_dir.iterdir()):
            if path.is_file():
                digest.update(path.name.encode("utf-8"))
                digest.update(b"\0")
                digest.update(path.read_bytes())
        return digest.hexdigest()
