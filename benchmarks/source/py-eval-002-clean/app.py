"""CWE-95 negative fixture."""

import ast


def parse_literal(value: str) -> object:
    return ast.literal_eval(value)
