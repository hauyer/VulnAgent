"""CWE-22 near-pair reducing input to one basename before file access."""

import os
from os.path import basename as leaf_name
from pathlib import Path as LocalPath


def read_document() -> str:
    requested = os.environ.get("DOCUMENT_NAME", "")
    candidate = LocalPath("documents") / leaf_name(requested)
    with open(candidate, encoding="utf-8") as handle:
        return handle.read()
