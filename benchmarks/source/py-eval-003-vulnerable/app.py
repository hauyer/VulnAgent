"""CWE-95 builtins alias fixture; static analysis only."""

import os
from builtins import eval as parse_value


def evaluate_setting() -> object:
    expression = os.getenv("VULNAGENT_EXPRESSION", "").strip()
    return parse_value(expression)
