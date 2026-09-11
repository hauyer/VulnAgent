"""Safe optional integrations with offline reverse-engineering tools.

These adapters accept an explicit authorization flag, invoke tools using argument
vectors, and never execute the supplied target.  They are intentionally kept at
the reverse-adapter boundary; higher-level analyzers receive them through
protocols rather than importing ``subprocess``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

_MAX_LOG_CHARS = 16_384
_DEFAULT_MAX_UNPACKED_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ToolRunResult:
    """JSON-safe, bounded outcome of one optional external-tool attempt."""

    tool: str
    status: str
    executed: bool = False
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    facts: dict[str, Any] | None = None
    error: str | None = None
    command: tuple[str, ...] = ()
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a strictly JSON-serializable form for artifact persistence."""
        return {
            "tool": self.tool,
            "status": self.status,
            "executed": self.executed,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "facts": self.facts or {},
            "error": self.error,
            "command": list(self.command),
            "truncated": self.truncated,
        }


class _SafeToolAdapter:
    """Shared authorization, process, log-bounding, and fingerprint safeguards."""

    tool_name: str

    def __init__(
        self,
        executable: str,
        timeout_seconds: float,
        runner: Callable[..., subprocess.CompletedProcess[str]],
        which: Callable[[str], str | None],
        max_log_chars: int,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if type(max_log_chars) is not int or max_log_chars <= 0:
            raise ValueError("max_log_chars must be a positive integer")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self._runner = runner
        self._which = which
        self.max_log_chars = max_log_chars

    def _preflight(self, path: str | Path, authorized: bool) -> tuple[Path | None, ToolRunResult | None, str | None]:
        if not authorized:
            return None, ToolRunResult(self.tool_name, "not_authorized", error="explicit authorization is required"), None
        input_path = Path(path).absolute()
        try:
            mode = input_path.stat().st_mode
        except OSError as exc:
            return None, ToolRunResult(self.tool_name, "invalid_input", error=f"cannot stat input: {exc}"), None
        if not stat.S_ISREG(mode):
            return None, ToolRunResult(self.tool_name, "invalid_input", error="input must be a regular file"), None
        resolved = self._which(self.executable)
        if not resolved:
            return None, ToolRunResult(self.tool_name, "unavailable", error=f"tool not found: {self.executable}"), None
        return input_path, None, resolved

    def _run(self, command: list[str]) -> ToolRunResult:
        try:
            completed = self._runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return ToolRunResult(self.tool_name, "timeout", executed=True, error=f"{self.tool_name} timed out", command=tuple(command))
        except OSError as exc:
            return ToolRunResult(self.tool_name, "error", error=f"cannot start {self.tool_name}: {exc}", command=tuple(command))
        stdout, stdout_truncated = _clip_text(completed.stdout, self.max_log_chars)
        stderr, stderr_truncated = _clip_text(completed.stderr, self.max_log_chars)
        if completed.returncode != 0:
            return ToolRunResult(
                self.tool_name,
                "error",
                executed=True,
                return_code=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                error=f"{self.tool_name} returned a non-zero status",
                command=tuple(command),
                truncated=stdout_truncated or stderr_truncated,
            )
        return ToolRunResult(
            self.tool_name,
            "ok",
            executed=True,
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            command=tuple(command),
            truncated=stdout_truncated or stderr_truncated,
        )


class UpxAdapter(_SafeToolAdapter):
    """Inspect or unpack UPX only for an explicitly authorized input."""

    tool_name = "upx"

    def __init__(
        self,
        executable: str = "upx",
        timeout_seconds: float = 15.0,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        max_log_chars: int = _MAX_LOG_CHARS,
    ) -> None:
        super().__init__(executable, timeout_seconds, runner, which, max_log_chars)

    def inspect(self, path: str | Path, *, authorized: bool = False) -> ToolRunResult:
        """List UPX metadata; this never decompresses, writes, or executes input."""
        input_path, failure, resolved = self._preflight(path, authorized)
        if failure:
            return failure
        assert input_path is not None and resolved is not None
        run = self._run([resolved, "-l", str(input_path)])
        return _with_facts(run, {"input": _file_fingerprint(input_path), "operation": "list"})

    def version(self, *, authorized: bool = False) -> ToolRunResult:
        """Capture the installed UPX version without opening a target."""
        if not authorized:
            return ToolRunResult(self.tool_name, "not_authorized", error="explicit authorization is required")
        resolved = self._which(self.executable)
        if not resolved:
            return ToolRunResult(self.tool_name, "unavailable", error=f"tool not found: {self.executable}")
        return _with_facts(self._run([resolved, "--version"]), {"operation": "version"})

    def unpack(
        self,
        path: str | Path,
        *,
        output_dir: str | Path,
        authorized: bool = False,
        max_output_bytes: int = _DEFAULT_MAX_UNPACKED_BYTES,
    ) -> ToolRunResult:
        """Decompress to a new private output path without ever replacing input.

        UPX is invoked as ``-d -o OUTPUT INPUT``.  The output is required to be a
        regular file, distinct from the input, and no larger than the supplied
        bound before its SHA-256 is recorded.  This method never runs the target.
        """
        if type(max_output_bytes) is not int or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be a positive integer")
        input_path, failure, resolved = self._preflight(path, authorized)
        if failure:
            return failure
        assert input_path is not None and resolved is not None
        try:
            base = Path(output_dir)
            base.mkdir(parents=True, exist_ok=True)
            private_dir = Path(tempfile.mkdtemp(prefix="upx-unpack-", dir=base))
            if os.name != "nt":
                os.chmod(private_dir, 0o700)
        except OSError as exc:
            return ToolRunResult(self.tool_name, "output_error", error=f"cannot create private output directory: {exc}")
        output_path = private_dir / f"{input_path.name}.unpacked"
        run = self._run([resolved, "-d", "-o", str(output_path), str(input_path)])
        facts: dict[str, Any] = {
            "input": _file_fingerprint(input_path),
            "operation": "unpack",
            "output_path": str(output_path),
        }
        if run.status != "ok":
            return _with_facts(run, facts)
        try:
            input_resolved = input_path.resolve(strict=True)
            output_resolved = output_path.resolve(strict=True)
            mode = output_resolved.stat().st_mode
            if output_resolved == input_resolved:
                return _with_facts(_replace_run(run, status="output_error", error="UPX output must not overwrite input"), facts)
            if not stat.S_ISREG(mode):
                return _with_facts(_replace_run(run, status="output_error", error="UPX output is not a regular file"), facts)
            size = output_resolved.stat().st_size
            if size > max_output_bytes:
                return _with_facts(_replace_run(run, status="output_too_large", error="UPX output exceeds max_output_bytes"), facts)
            facts["output"] = _file_fingerprint(output_resolved)
            return _with_facts(run, facts)
        except OSError as exc:
            return _with_facts(_replace_run(run, status="output_error", error=f"invalid UPX output: {exc}"), facts)


class Radare2Adapter(_SafeToolAdapter):
    """Obtain bounded function, CFG, and optional built-in pdc facts via r2."""

    tool_name = "radare2"

    def __init__(
        self,
        executable: str = "r2",
        timeout_seconds: float = 20.0,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        max_log_chars: int = _MAX_LOG_CHARS,
        max_functions: int = 256,
        max_pseudocode_chars: int = 8_192,
    ) -> None:
        super().__init__(executable, timeout_seconds, runner, which, max_log_chars)
        if type(max_functions) is not int or max_functions <= 0:
            raise ValueError("max_functions must be a positive integer")
        if type(max_pseudocode_chars) is not int or max_pseudocode_chars <= 0:
            raise ValueError("max_pseudocode_chars must be a positive integer")
        self.max_functions = max_functions
        self.max_pseudocode_chars = max_pseudocode_chars

    def version(self, *, authorized: bool = False) -> ToolRunResult:
        """Capture r2 version without opening a target."""
        if not authorized:
            return ToolRunResult(self.tool_name, "not_authorized", error="explicit authorization is required")
        resolved = self._which(self.executable)
        if not resolved:
            return ToolRunResult(self.tool_name, "unavailable", error=f"tool not found: {self.executable}")
        return _with_facts(self._run([resolved, "-v"]), {"operation": "version"})

    def inspect(
        self,
        path: str | Path,
        *,
        authorized: bool = False,
        include_pseudocode: bool = True,
        tool_versions: bool = False,
    ) -> ToolRunResult:
        """Run distinct r2 commands and normalize their individual outputs.

        A combined ``-q0`` process cannot reliably delimit outputs of multiple
        commands.  Each JSON-producing command therefore runs in a separate r2
        process: ``aa;aflj`` and ``aa;agfj``.  ``pdc`` is requested independently
        only at validated numeric function offsets.
        """
        input_path, failure, resolved = self._preflight(path, authorized)
        if failure:
            return failure
        assert input_path is not None and resolved is not None
        functions_run = self._run([resolved, "-q", "-c", "aa;aflj", str(input_path)])
        if functions_run.status != "ok":
            return _with_facts(functions_run, {"input": _file_fingerprint(input_path), "operation": "aflj"})
        try:
            functions = parse_radare2_functions(functions_run.stdout, self.max_functions)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return _with_facts(_replace_run(functions_run, status="invalid_output", error=f"invalid radare2 aflj JSON: {exc}"), {"input": _file_fingerprint(input_path), "operation": "aflj"})

        # Managed or fully packed images may legitimately expose no native
        # functions to radare2. In that case agfj can emit an empty stream; a
        # valid aflj=[] result is still a successful bounded inspection.
        if not functions:
            facts = {
                "input": _file_fingerprint(input_path),
                "functions": [],
                "cfg": {},
                "pseudocode": {},
                "pseudocode_failures": [],
                "source": "radare2",
            }
            if tool_versions:
                facts["tool_version"] = self._run([resolved, "-v"]).as_dict()
            return _with_facts(functions_run, facts)

        graphs_run = self._run([resolved, "-q", "-c", "aa;agfj", str(input_path)])
        if graphs_run.status != "ok":
            return _with_facts(graphs_run, {"input": _file_fingerprint(input_path), "operation": "agfj", "functions": functions})
        try:
            cfg = parse_radare2_graphs(graphs_run.stdout, self.max_functions)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return _with_facts(_replace_run(graphs_run, status="invalid_output", error=f"invalid radare2 agfj JSON: {exc}"), {"input": _file_fingerprint(input_path), "operation": "agfj", "functions": functions})

        pseudocode: dict[str, str] = {}
        failures: list[dict[str, Any]] = []
        version_record: dict[str, Any] | None = None
        if tool_versions:
            version_run = self._run([resolved, "-v"])
            version_record = version_run.as_dict()
        log_truncated = functions_run.truncated or graphs_run.truncated
        if include_pseudocode:
            for function in functions:
                address = function["address"]
                command = [resolved, "-q", "-c", f"aa;pdc @ 0x{address:x}", str(input_path)]
                pdc_run = self._run(command)
                log_truncated |= pdc_run.truncated
                if pdc_run.status != "ok":
                    failures.append({"address": address, "status": pdc_run.status, "error": pdc_run.error, "return_code": pdc_run.return_code})
                    continue
                code, clipped = _clip_text(pdc_run.stdout, self.max_pseudocode_chars)
                log_truncated |= clipped
                pseudocode[f"0x{address:x}"] = code
        facts = {
            "input": _file_fingerprint(input_path),
            "functions": functions,
            "cfg": cfg,
            "pseudocode": pseudocode,
            "pseudocode_failures": failures,
            "source": "radare2",
        }
        if version_record is not None:
            facts["tool_version"] = version_record
        logs = "\n".join((functions_run.stdout, functions_run.stderr, graphs_run.stdout, graphs_run.stderr))
        return ToolRunResult(
            self.tool_name,
            "partial" if failures else "ok",
            executed=True,
            return_code=0,
            stdout=logs[: self.max_log_chars],
            stderr="",
            facts=facts,
            error="one or more pdc requests failed" if failures else None,
            command=functions_run.command + graphs_run.command,
            truncated=log_truncated or len(logs) > self.max_log_chars,
        )


def parse_radare2_json(output: str, max_functions: int = 10_000) -> dict[str, Any]:
    """Compatibility parser for a NUL-separated ``aflj`` / ``agfj`` fixture."""
    if type(max_functions) is not int or max_functions <= 0:
        raise ValueError("max_functions must be a positive integer")
    chunks = [chunk.strip() for chunk in output.split("\0") if chunk.strip()]
    if len(chunks) != 2:
        raise ValueError("expected exactly two NUL-separated JSON arrays")
    return {
        "functions": parse_radare2_functions(chunks[0], max_functions),
        "cfg": parse_radare2_graphs(chunks[1], max_functions),
        "source": "radare2",
    }


def parse_radare2_functions(output: str, max_functions: int = 10_000) -> list[dict[str, Any]]:
    """Validate one ``aflj`` JSON array without accepting concatenated output."""
    raw = _json_array(output)
    functions: list[dict[str, Any]] = []
    for row in raw[:max_functions]:
        if not isinstance(row, dict):
            continue
        address = _radare_address(row)
        if address is None:
            continue
        functions.append({
            "name": str(row.get("name", f"fcn.{address:x}"))[:256],
            "address": address,
            "size": _nonnegative_int(row.get("size")),
            "source": "radare2",
        })
    return functions


def parse_radare2_graphs(output: str, max_functions: int = 10_000) -> dict[str, list[str]]:
    """Normalize ``agfj`` into block-address -> successor-address adjacency."""
    raw = _json_array(output)
    cfg: dict[str, list[str]] = {}
    for graph in raw[:max_functions]:
        if not isinstance(graph, dict):
            continue
        blocks = graph.get("blocks")
        if not isinstance(blocks, list):
            continue
        for block in blocks[:max_functions]:
            if not isinstance(block, dict):
                continue
            address = _radare_address(block)
            if address is None:
                continue
            source = f"0x{address:x}"
            successors = [f"0x{target:x}" for target in (block.get("jump"), block.get("fail")) if _is_int(target)]
            cfg[source] = list(dict.fromkeys(successors))
    return cfg


def _json_array(output: str) -> list[Any]:
    value = json.loads(output.strip().rstrip("\0").strip())
    if not isinstance(value, list):
        raise ValueError("expected JSON array")
    return value


def _with_facts(run: ToolRunResult, facts: dict[str, Any]) -> ToolRunResult:
    merged = dict(run.facts or {})
    merged.update(facts)
    return _replace_run(run, facts=merged)


def _replace_run(run: ToolRunResult, **changes: Any) -> ToolRunResult:
    values = run.__dict__.copy()
    values.update(changes)
    return ToolRunResult(**values)


def _clip_text(value: object, maximum: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ""
    return text[:maximum], len(text) > maximum


def _file_fingerprint(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _radare_address(row: dict[str, Any]) -> int | None:
    """Accept the ``offset`` and radare2 6.x ``addr`` JSON spellings."""

    value = row.get("offset")
    if not _is_int(value):
        value = row.get("addr")
    return value if _is_int(value) and value >= 0 else None


def _nonnegative_int(value: object) -> int:
    return value if _is_int(value) and value >= 0 else 0
