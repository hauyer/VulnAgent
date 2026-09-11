"""CWE-22 positive fixture; static analysis only."""


def read_user_path() -> str:
    requested = input("path: ")
    with open(requested, encoding="utf-8") as handle:
        return handle.read()
