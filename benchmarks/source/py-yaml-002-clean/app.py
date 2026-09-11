"""CWE-502 PyYAML negative fixture."""

import yaml


def decode_document(payload: str) -> object:
    return yaml.load(payload, Loader=yaml.SafeLoader)
