"""CWE-502 positive fixture; static analysis only."""

import pickle


def decode_payload() -> object:
    payload = input("payload: ").encode()
    return pickle.loads(payload)
