"""Centralized Source / Sink / Sanitizer registry (V0.6 deep source analysis).

The auditor consumes these registries instead of ad-hoc module-level
frozensets, so the catalog is one place to extend (new sinks, sources,
sanitizers) without touching the scanning logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- canonical sink categories -------------------------------------------------
COMMAND = "command"
SQL = "sql"
PATH = "path"
DESERIALIZATION = "deserialization"
CODE_EXECUTION = "code_execution"

ALL_CATEGORIES = frozenset(
    {COMMAND, SQL, PATH, DESERIALIZATION, CODE_EXECUTION}
)


@dataclass(frozen=True, slots=True)
class SinkRegistry:
    """Known dangerous APIs grouped by vulnerability category."""

    command: frozenset[str] = frozenset({"os.system", "os.popen"})
    subprocess: frozenset[str] = frozenset(
        {
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "subprocess.run",
        }
    )
    path: frozenset[str] = frozenset(
        {
            "open",
            "io.open",
            "os.open",
            "pathlib.Path",
            "flask.send_file",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.move",
            "shutil.rmtree",
        }
    )
    deserialization: frozenset[str] = frozenset(
        {
            "pickle.load",
            "pickle.loads",
            "marshal.load",
            "marshal.loads",
            "dill.load",
            "dill.loads",
            "yaml.load",
        }
    )
    code_execution: frozenset[str] = frozenset(
        {"eval", "exec", "builtins.eval", "builtins.exec"}
    )

    @property
    def all_sinks(self) -> frozenset[str]:
        return frozenset().union(
            self.command,
            self.subprocess,
            self.path,
            self.deserialization,
            self.code_execution,
        )


@dataclass(frozen=True, slots=True)
class SourceRegistry:
    """Untrusted-data origins: calls, dotted suffixes and attributes."""

    calls: frozenset[str] = frozenset(
        {
            "input",
            "builtins.input",
            "os.getenv",
            "os.environ.get",
            "flask.request.get_json",
        }
    )
    suffixes: tuple[str, ...] = (
        "request.args.get",
        "request.form.get",
        "request.values.get",
        "request.cookies.get",
        "request.headers.get",
        "request.get_json",
    )
    attributes: frozenset[str] = frozenset(
        {
            "request.args",
            "request.form",
            "request.values",
            "request.cookies",
            "request.headers",
            "request.json",
            "sys.argv",
            "os.environ",
        }
    )


@dataclass(frozen=True, slots=True)
class SanitizerRegistry:
    """Sanitizers that neutralize a category: name -> category."""

    entries: dict[str, str] = field(
        default_factory=lambda: {
            "shlex.quote": COMMAND,
            "os.path.basename": PATH,
            "werkzeug.utils.secure_filename": PATH,
        }
    )

    def category_for(self, name: str) -> str | None:
        return self.entries.get(name)


COMMAND_SINKS = SinkRegistry().command
SUBPROCESS_SINKS = SinkRegistry().subprocess
DESERIALIZATION_SINKS = SinkRegistry().deserialization
PATH_SINKS = SinkRegistry().path
CODE_EXECUTION_SINKS = SinkRegistry().code_execution
SOURCE_CALLS = SourceRegistry().calls
REQUEST_SOURCE_SUFFIXES = SourceRegistry().suffixes
SOURCE_ATTRIBUTES = SourceRegistry().attributes
SANITIZERS = SanitizerRegistry().entries


__all__ = [
    "ALL_CATEGORIES",
    "COMMAND",
    "SQL",
    "PATH",
    "DESERIALIZATION",
    "CODE_EXECUTION",
    "SinkRegistry",
    "SourceRegistry",
    "SanitizerRegistry",
]
