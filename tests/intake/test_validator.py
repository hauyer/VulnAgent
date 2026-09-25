"""Tests for the read-only target intake validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.intake import (
    Authorization,
    DefaultTargetIntake,
    DatasetRole,
    LabelLeakError,
    TargetManifest,
    assert_ground_truth_isolated,
    fingerprint_target,
    find_label_leaks,
)
from vulnagent.intake import validator as validator_module


def _target(tmp_path: Path, content: bytes = b"x", name: str = "app.py") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _manifest(tmp_path: Path, target: Path, **overrides) -> TargetManifest:
    values = dict(
        sample_id="s1",
        source_name="demo",
        role=DatasetRole.TRAIN,
        revision="deadbeef",
        target_path=str(target),
        target_sha256=fingerprint_target(target),
        license_record="edu",
    )
    values.update(overrides)
    return TargetManifest(**values)


def _validate(tmp_path: Path, manifest: TargetManifest) -> object:
    return DefaultTargetIntake().validate(
        manifest, authorized_roots=[tmp_path], base_path=tmp_path
    )


def test_valid_file_is_accepted(tmp_path: Path) -> None:
    decision = _validate(tmp_path, _manifest(tmp_path, _target(tmp_path)))
    assert decision.accepted is True
    assert decision.reason_codes == ["accepted"]
    assert decision.checked_sha256 is not None


def test_valid_directory_tree_is_accepted(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("a")
    (project / "b.py").write_text("bb")
    manifest = _manifest(tmp_path, project)
    decision = _validate(tmp_path, manifest)
    assert decision.accepted is True


def test_missing_revision_is_rejected(tmp_path: Path) -> None:
    decision = _validate(tmp_path, _manifest(tmp_path, _target(tmp_path), revision=" "))
    assert decision.accepted is False
    assert "missing_revision" in decision.reason_codes


def test_missing_license_is_rejected(tmp_path: Path) -> None:
    decision = _validate(
        tmp_path, _manifest(tmp_path, _target(tmp_path), license_record="")
    )
    assert "missing_license" in decision.reason_codes


def test_invalid_sha256_format_is_rejected(tmp_path: Path) -> None:
    decision = _validate(
        tmp_path,
        _manifest(tmp_path, _target(tmp_path), target_sha256="not-a-hash"),
    )
    assert "invalid_sha256" in decision.reason_codes


@pytest.mark.parametrize(
    "raw",
    [r"\\server\share\app.py", "http://example.com/app.py", r"\\?\C:\app.py"],
)
def test_network_paths_are_rejected(tmp_path: Path, raw: str) -> None:
    manifest = _manifest(tmp_path, _target(tmp_path), target_path=raw)
    decision = _validate(tmp_path, manifest)
    assert "network_path" in decision.reason_codes
    assert decision.checked_sha256 is None


def test_absolute_path_outside_roots_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_app.py"
    manifest = _manifest(tmp_path, _target(tmp_path), target_path=str(outside))
    decision = _validate(tmp_path, manifest)
    assert "path_escape" in decision.reason_codes


def test_relative_parent_escape_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, _target(tmp_path), target_path="../escape.py")
    decision = _validate(tmp_path, manifest)
    assert "path_escape" in decision.reason_codes


def test_missing_target_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path, _target(tmp_path), target_path=str(tmp_path / "nope.py")
    )
    decision = _validate(tmp_path, manifest)
    assert "missing_target" in decision.reason_codes


def test_sha256_mismatch_is_rejected(tmp_path: Path) -> None:
    target = _target(tmp_path)
    manifest = _manifest(
        tmp_path, target, target_sha256="a" * 64
    )
    decision = _validate(tmp_path, manifest)
    assert "sha256_mismatch" in decision.reason_codes


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    target = _target(tmp_path, content=b"")
    manifest = _manifest(tmp_path, target)
    decision = _validate(tmp_path, manifest)
    assert "size_limit" in decision.reason_codes


def test_oversized_file_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(validator_module, "_MAX_FILE_BYTES", 3)
    target = _target(tmp_path, content=b"too-big")
    decision = _validate(tmp_path, _manifest(tmp_path, target))
    assert "size_limit" in decision.reason_codes


def test_static_read_denied_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        _target(tmp_path),
        authorization=Authorization(static_read=False),
    )
    decision = _validate(tmp_path, manifest)
    assert "authorization_mismatch" in decision.reason_codes


def test_dynamic_run_without_statement_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        _target(tmp_path),
        authorization=Authorization(static_read=True, dynamic_run=True),
    )
    decision = _validate(tmp_path, manifest)
    assert "authorization_mismatch" in decision.reason_codes


def test_authorized_dynamic_target_is_accepted(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        _target(tmp_path),
        authorization=Authorization(
            static_read=True, dynamic_run=True, statement="granted for course"
        ),
    )
    decision = _validate(tmp_path, manifest)
    assert decision.accepted is True
    assert decision.dynamic_allowed is True


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    outside_dir = tmp_path.parent / f"outside_{tmp_path.name}"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "app.py"
    outside_file.write_bytes(b"x")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(outside_file)
    except OSError:
        pytest.skip("symlink creation requires privileges on this host")
    manifest = _manifest(tmp_path, link)
    decision = _validate(tmp_path, manifest)
    assert "path_escape" in decision.reason_codes


def test_find_label_leaks_detects_hidden_reference(tmp_path: Path) -> None:
    target = _target(tmp_path)
    manifest = _manifest(
        tmp_path,
        target,
        role=DatasetRole.HELD_OUT,
        ground_truth_ref="private-label-001",
    )
    leaks = find_label_leaks(manifest, {"prompt": "analyze private-label-001"})
    assert leaks == ["prompt"]
    assert find_label_leaks(manifest, {"prompt": "clean input"}) == []


def test_assert_ground_truth_isolated_raises(tmp_path: Path) -> None:
    target = _target(tmp_path)
    manifest = _manifest(tmp_path, target, ground_truth_ref="secret-ref")
    with pytest.raises(LabelLeakError):
        assert_ground_truth_isolated(
            manifest, {"task_metadata": "ref=secret-ref"}
        )
