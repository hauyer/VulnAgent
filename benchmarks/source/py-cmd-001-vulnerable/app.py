"""CWE-78 positive fixture; never execute this file."""

import subprocess


def run_user_command() -> subprocess.CompletedProcess[str]:
    command = input("command: ")
    return subprocess.run(command, shell=True, check=False, text=True)
