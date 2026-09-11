"""CWE-78 negative fixture."""

import subprocess


def show_value(value: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["echo", value], shell=False, check=False, text=True)
