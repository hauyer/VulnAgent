"""CWE-502 negative fixture."""

import json


def decode_payload(payload: str) -> object:
    return json.loads(payload)
