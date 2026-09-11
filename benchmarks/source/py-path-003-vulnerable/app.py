"""CWE-22 composed pathlib/open fixture; static analysis only."""

import os
from pathlib import Path as LocalPath


def read_document() -> str:
    requested = os.environ.get("DOCUMENT_NAME", "")
    candidate = LocalPath("documents") / requested
    with open(candidate, encoding="utf-8") as handle:
        return handle.read()
