"""V0.7 Binary Intelligence: dangerous / external-input API catalog.

A registry-style catalog of runtime library APIs that either introduce
external input into a process or reach a dangerous sink.  The catalog is the
binary-side counterpart of ``audit/registry.py`` for source analysis: both
engines share the same ``category`` vocabulary so that cross-engine fusion can
compare like for like.
"""

from __future__ import annotations

# Dangerous sinks reachable via an import thunk or direct IAT call.
# symbol -> category (matches the source-analysis category vocabulary).
DANGEROUS_APIS: dict[str, str] = {
    # Buffer overwrite / unbounded copies.
    "strcpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "sprintf": "buffer_overflow",
    "vsprintf": "buffer_overflow",
    "swprintf": "buffer_overflow",
    "memcpy": "buffer_overflow",
    "memmove": "buffer_overflow",
    "wcscpy": "buffer_overflow",
    "wcscat": "buffer_overflow",
    # Command execution.
    "system": "command_execution",
    "popen": "command_execution",
    "_popen": "command_execution",
    "execl": "command_execution",
    "execlp": "command_execution",
    "execle": "command_execution",
    "execv": "command_execution",
    "execvp": "command_execution",
    "execve": "command_execution",
    "winexec": "command_execution",
    "ShellExecuteA": "command_execution",
    "ShellExecuteW": "command_execution",
    # Format-string sinks (non-constant format argument is dangerous).
    "printf": "format_string",
    "fprintf": "format_string",
    "sprintf": "format_string",
    "snprintf": "format_string",
    "vsprintf": "format_string",
    "vprintf": "format_string",
}

# APIs that pull data from outside the process into a buffer.
# symbol -> source kind.
INPUT_APIS: dict[str, str] = {
    "gets": "stdin",
    "fgets": "file",
    "fread": "file",
    "scanf": "stdin",
    "fscanf": "file",
    "sscanf": "internal_string",
    "read": "file_descriptor",
    "recv": "network",
    "recvfrom": "network",
    "fgetws": "file",
    "getenv": "environment",
    "argv": "process_argument",
}


def dangerous_category(symbol: str) -> str | None:
    return DANGEROUS_APIS.get(symbol.casefold())


def input_source_kind(symbol: str) -> str | None:
    return INPUT_APIS.get(symbol.casefold())
