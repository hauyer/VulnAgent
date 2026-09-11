"""CWE-502 PyYAML positive fixture; static analysis only."""

import yaml


def decode_document() -> object:
    payload = input("yaml: ")
    return yaml.load(payload)
