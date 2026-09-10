"""Small CWE identifier validation helper; no external knowledge is bundled."""

import re


def is_cwe_id(value: str) -> bool:
    return re.fullmatch(r"CWE-[1-9][0-9]*", value) is not None

