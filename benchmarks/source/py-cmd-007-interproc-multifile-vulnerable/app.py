"""CWE-78 positive fixture entry: taints flow into cross-file helpers."""

from helpers import run_build


def main() -> None:
    version = input("version: ")
    run_build(version)
