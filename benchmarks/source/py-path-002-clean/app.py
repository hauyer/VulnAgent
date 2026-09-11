"""CWE-22 negative fixture."""

from pathlib import Path


def read_fixed_file() -> str:
    return (Path(__file__).resolve().parent / "data.txt").read_text(encoding="utf-8")
