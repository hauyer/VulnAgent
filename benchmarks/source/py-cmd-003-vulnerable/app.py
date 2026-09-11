"""CWE-78 alias and transformed-input fixture; static analysis only."""

import os
import subprocess as process_api


def run_diagnostic() -> process_api.CompletedProcess[str]:
    command = os.getenv("VULNAGENT_DIAGNOSTIC", "").strip()
    return process_api.run(command, shell=True, check=False, text=True)
