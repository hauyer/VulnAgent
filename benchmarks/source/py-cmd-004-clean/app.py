"""CWE-78 near-pair using validated argv and no command shell."""

import re
import subprocess as process_api


def ping_host(host: str) -> process_api.CompletedProcess[str] | None:
    if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) is None:
        return None
    return process_api.run(
        ["ping", "-n", "1", host],
        shell=False,
        check=False,
        text=True,
    )
