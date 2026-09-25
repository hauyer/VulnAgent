"""Content hashing for target admission.

A single file is hashed directly.  A project directory is fingerprinted
deterministically over its sorted relative file paths and each file's digest,
so the same pinned content always yields the same value regardless of
filesystem ordering.  These helpers are also reused by later reproduction and
artifact records.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_files(root: Path) -> list[Path]:
    return sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    )


def fingerprint_target(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file or a directory tree.

    For a directory the digest covers, for every file in sorted path order,
    the UTF-8 relative path, a NUL separator and the file digest.  The
    directory fingerprint therefore changes if a file is added, removed,
    renamed or modified.
    """

    if path.is_file():
        return sha256_file(path)

    digest = hashlib.sha256()
    for item in _iter_files(path):
        rel = item.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(sha256_file(item).encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


def target_size(path: Path) -> int:
    """Return the byte size of a file, or the aggregate size of a tree."""

    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in _iter_files(path))
