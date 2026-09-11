"""Tests for the binary symbol-observability benchmark controls."""

from pathlib import Path
from types import SimpleNamespace

from experiments import run_binary_benchmark


def test_compile_controls_symbol_stripping(monkeypatch, tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(run_binary_benchmark.subprocess, "run", fake_run)
    source = tmp_path / "fixture.c"
    rich = tmp_path / "rich.exe"
    stripped = tmp_path / "stripped.exe"

    run_binary_benchmark._compile(
        source,
        rich,
        "gcc",
        strip_symbols=False,
    )
    run_binary_benchmark._compile(
        source,
        stripped,
        "gcc",
        strip_symbols=True,
    )

    assert "-s" not in commands[0]
    assert "-s" in commands[1]
    assert commands[0][-2:] == ["-o", str(rich)]
    assert commands[1][-2:] == ["-o", str(stripped)]


def test_binary_benchmark_has_paired_symbol_profiles() -> None:
    assert run_binary_benchmark._COMPILATION_PROFILES == (
        ("vulnagent_binary_symbol_rich", False, "symbol-rich"),
        ("vulnagent_binary_stripped", True, "stripped"),
    )
