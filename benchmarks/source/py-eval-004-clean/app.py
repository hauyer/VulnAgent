"""CWE-95 near-pair resolving the same alias to ast.literal_eval."""

import os
from ast import literal_eval as parse_value


def evaluate_setting() -> object:
    expression = os.getenv("VULNAGENT_EXPRESSION", "").strip()
    return parse_value(expression)
