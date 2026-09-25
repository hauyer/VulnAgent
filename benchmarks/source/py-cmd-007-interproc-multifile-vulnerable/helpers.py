"""CWE-78 positive fixture: cross-file helper chain; never execute."""

import subprocess


def execute_shell(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, shell=True, check=False, text=True)


def run_build(command: str) -> subprocess.CompletedProcess[str]:
    return execute_shell(command)
