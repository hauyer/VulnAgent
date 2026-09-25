"""CWE-78 positive fixture: three-layer interprocedural chain; never execute."""

import subprocess


def execute_shell(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, shell=True, check=False, text=True)


def run_build(command: str) -> subprocess.CompletedProcess[str]:
    return execute_shell(command)


def deploy(version: str) -> subprocess.CompletedProcess[str]:
    command = "deploy --version " + version
    return run_build(command)


def main() -> None:
    version = input("version: ")
    deploy(version)
