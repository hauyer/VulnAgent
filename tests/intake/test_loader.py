"""Tests for manifest loading and alias normalization."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.intake import (
    DatasetRole,
    fingerprint_target,
    load_manifest,
    load_manifest_dir,
)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("print(1)")
    return project


def test_load_practice_plan_yaml_format(tmp_path: Path) -> None:
    project = _project(tmp_path)
    digest = fingerprint_target(project)
    yaml_text = f"""
sample_id: project-a-case-001
dataset: historical_open_source
family_id: parser-boundary
target_type: source
language: c
project: project-a
repository: https://example.invalid/project-a
revision: aaa111
fixed_revision: bbb222
source_sha256: {digest}
license: MIT
authorization: local_open_source_research
dynamic_allowed: false
ground_truth_ref: private-label-1
build_profile: linux_clang_asan
time_budget_seconds: 300
memory_budget_mb: 2048
target_path: proj
"""
    source = tmp_path / "case.yaml"
    source.write_text(yaml_text, encoding="utf-8")
    manifest = load_manifest(source)
    assert manifest.sample_id == "project-a-case-001"
    assert manifest.target_kind.value == "source"
    assert manifest.target_sha256 == digest
    assert manifest.license_record == "MIT"
    assert manifest.upstream_uri == "https://example.invalid/project-a"
    assert manifest.fixed_revision == "bbb222"
    assert manifest.authorization.statement == "local_open_source_research"
    assert manifest.dynamic_allowed is False
    assert manifest.static_allowed is True
    assert manifest.ground_truth_ref == "private-label-1"


def test_load_guide_json_format(tmp_path: Path) -> None:
    project = _project(tmp_path)
    digest = fingerprint_target(project)
    source = tmp_path / "case.json"
    source.write_text(
        (
            '{"sample_id": "g1", "source_name": "guide-proj", '
            '"role": "held_out", "revision": "c1", "target_path": "proj", '
            f'"target_sha256": "{digest}", "license_record": "Apache-2.0", '
            '"authorization": {"static_read": true, "dynamic_run": true, '
            '"statement": "authorized"}}'
        ),
        encoding="utf-8",
    )
    manifest = load_manifest(source)
    assert manifest.role == DatasetRole.HELD_OUT
    assert manifest.dynamic_allowed is True
    assert manifest.authorization.dynamic_run is True
    assert manifest.authorization.statement == "authorized"


def test_flat_dynamic_allowed_folds_into_authorization(tmp_path: Path) -> None:
    project = _project(tmp_path)
    digest = fingerprint_target(project)
    source = tmp_path / "case.yaml"
    source.write_text(
        (
            "sample_id: d1\nsource_name: p\nrole: exploratory\n"
            "revision: r1\ntarget_path: proj\n"
            f"target_sha256: {digest}\nlicense_record: BSD\n"
            "dynamic_allowed: true\nauthorization: granted\n"
        ),
        encoding="utf-8",
    )
    manifest = load_manifest(source)
    assert manifest.dynamic_allowed is True
    assert manifest.authorization.statement == "granted"


def test_missing_required_field_raises(tmp_path: Path) -> None:
    source = tmp_path / "bad.yaml"
    source.write_text("sample_id: x\nsource_name: p\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(source)


def test_load_manifest_dir_deduplicates_and_skips_templates(tmp_path: Path) -> None:
    project_a = tmp_path / "a"
    project_a.mkdir()
    (project_a / "app.py").write_text("a")
    project_b = tmp_path / "b"
    project_b.mkdir()
    (project_b / "app.py").write_text("b")
    ha = fingerprint_target(project_a)
    hb = fingerprint_target(project_b)

    def _write(name: str, sid: str, path: str, digest: str) -> None:
        (tmp_path / name).write_text(
            (
                f"sample_id: {sid}\nsource_name: p\nrole: train\n"
                f"revision: r\ntarget_path: {path}\ntarget_sha256: {digest}\n"
                "license_record: MIT\n"
            ),
            encoding="utf-8",
        )

    _write("one.yaml", "s1", "a", ha)
    _write("two.yaml", "s2", "b", hb)
    (tmp_path / "_skip.yaml").write_text("sample_id: z", encoding="utf-8")
    (tmp_path / "TEMPLATE.yaml").write_text("sample_id: t", encoding="utf-8")

    manifests = load_manifest_dir(tmp_path)
    assert [m.sample_id for m in manifests] == ["s1", "s2"]


def test_load_manifest_dir_rejects_duplicate_ids(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text("x")
    digest = fingerprint_target(project)
    body = (
        "sample_id: dup\nsource_name: p\nrole: train\nrevision: r\n"
        f"target_path: p\ntarget_sha256: {digest}\nlicense_record: MIT\n"
    )
    (tmp_path / "one.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "two.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest_dir(tmp_path)
