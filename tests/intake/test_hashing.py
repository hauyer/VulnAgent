"""Tests for admission content hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

from vulnagent.intake.hashing import fingerprint_target, sha256_file, target_size


def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_bytes(b"hello world")
    assert sha256_file(path) == hashlib.sha256(b"hello world").hexdigest()


def test_fingerprint_file_equals_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_bytes(b"data")
    assert fingerprint_target(path) == sha256_file(path)


def test_directory_fingerprint_is_stable(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.py").write_text("a")
    (tmp_path / "sub" / "b.py").write_text("bb")
    first = fingerprint_target(tmp_path)
    second = fingerprint_target(tmp_path)
    assert first == second


def test_directory_fingerprint_independent_of_creation_order(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    for root in (left, right):
        (root / "pkg").mkdir(parents=True)
    (left / "a.py").write_text("x")
    (left / "pkg" / "b.py").write_text("yy")
    (right / "pkg" / "b.py").write_text("yy")
    (right / "a.py").write_text("x")
    assert fingerprint_target(left) == fingerprint_target(right)


def test_directory_fingerprint_changes_on_content_edit(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x")
    before = fingerprint_target(tmp_path)
    (tmp_path / "a.py").write_text("changed")
    assert fingerprint_target(tmp_path) != before


def test_directory_fingerprint_changes_when_file_added(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x")
    before = fingerprint_target(tmp_path)
    (tmp_path / "b.py").write_text("y")
    assert fingerprint_target(tmp_path) != before


def test_target_size_aggregates_tree(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("abc")
    (tmp_path / "b.py").write_text("de")
    assert target_size(tmp_path) == 5
