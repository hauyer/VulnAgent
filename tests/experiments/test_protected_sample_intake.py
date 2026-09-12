"""Protected closed-source sample intake stays truthful and read-only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.audit_protected_samples import audit_manifests, load_manifest


ROOT = Path(__file__).resolve().parents[2]


def _sample(
    sample_id: str,
    kind: str,
    software_name: str,
    local_path: str,
    digest: str,
) -> dict[str, object]:
    return {
        "sample_id": sample_id,
        "acquisition_status": "materialized",
        "qualification": "strict_closed_source",
        "software": {"name": software_name, "version": "1.0", "closed_source": True},
        "protection": {"kind": kind, "product": f"test-{kind}", "version": "1.0"},
        "provenance": {
            "source_uri": "https://vendor.invalid/download",
            "license_or_terms": "Owner-supplied classroom static-analysis authorization.",
            "acquired_at": "2026-09-11",
        },
        "authorization": {
            "static_analysis": True,
            "tool_transform": False,
            "dynamic_execution": False,
            "statement": "Static read-only analysis is explicitly authorized.",
        },
        "local_path": local_path,
        "sha256": digest,
        "file_format": "PE",
        "architecture": "x86-64",
        "expected_observations": [f"{kind} marker supplied by the owner"],
    }


def _write_manifest(path: Path, kind: str, samples: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "suite_id": f"test-{kind}",
                "protection_kind": kind,
                "samples": samples,
            }
        ),
        encoding="utf-8",
    )


def test_repository_manifests_contain_two_authorized_external_targets_each() -> None:
    manifests = [
        load_manifest(ROOT / "benchmarks/packed/manifest.json"),
        load_manifest(ROOT / "benchmarks/obfuscated/manifest.json"),
    ]

    assert [item["protection_kind"] for item in manifests] == [
        "packing",
        "obfuscation",
    ]
    assert all(len(item["samples"]) == 2 for item in manifests)
    samples = [sample for manifest in manifests for sample in manifest["samples"]]
    assert all(sample["acquisition_status"] == "pending_user_supplied" for sample in samples)
    assert all(sample["software"]["closed_source"] is True for sample in samples)
    assert all(sample["authorization"]["static_analysis"] is True for sample in samples)
    assert all(sample["authorization"]["dynamic_execution"] is False for sample in samples)


def test_distributable_checkout_reports_missing_protected_materials_honestly() -> None:
    result = audit_manifests(
        [
            ROOT / "benchmarks/packed/manifest.json",
            ROOT / "benchmarks/obfuscated/manifest.json",
        ]
    )

    assert result["strict_requirement_met"] is False
    assert result["ready_distinct_software"] == {"obfuscation": 0, "packing": 0}
    assert all(row["target_executed"] is False for row in result["samples"])
    assert all(row["status"] == "pending_user_supplied" for row in result["samples"])


def test_two_distinct_materialized_samples_per_kind_pass_intake(tmp_path: Path) -> None:
    manifests: list[Path] = []
    for kind in ("packing", "obfuscation"):
        manifest_path = tmp_path / kind / "manifest.json"
        materials = manifest_path.parent / "materials"
        materials.mkdir(parents=True)
        samples: list[dict[str, object]] = []
        for index in (1, 2):
            payload = b"MZ" + kind.encode() + bytes([index])
            filename = f"sample-{index}.exe"
            (materials / filename).write_bytes(payload)
            samples.append(
                _sample(
                    f"{kind}-{index}",
                    kind,
                    f"Vendor Product {kind} {index}",
                    f"materials/{filename}",
                    hashlib.sha256(payload).hexdigest(),
                )
            )
        _write_manifest(manifest_path, kind, samples)
        manifests.append(manifest_path)

    result = audit_manifests(manifests)

    assert result["strict_requirement_met"] is True
    assert result["ready_distinct_software"] == {"obfuscation": 2, "packing": 2}
    assert all(row["intake_ready"] is True for row in result["samples"])
    assert all(row["tool_transform_executed"] is False for row in result["samples"])


def test_materialized_sample_requires_provenance_and_static_authorization(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "packing" / "manifest.json"
    sample = _sample("packed-1", "packing", "Product", "materials/a.exe", "0" * 64)
    sample["authorization"]["static_analysis"] = False  # type: ignore[index]
    _write_manifest(manifest_path, "packing", [sample])

    with pytest.raises(ValueError, match="static-analysis authorization"):
        load_manifest(manifest_path)


def test_hash_mismatch_and_path_escape_are_rejected_without_execution(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "packing" / "manifest.json"
    materials = manifest_path.parent / "materials"
    materials.mkdir(parents=True)
    (materials / "changed.exe").write_bytes(b"MZchanged")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZoutside")
    samples = [
        _sample("changed", "packing", "Product A", "materials/changed.exe", "0" * 64),
        _sample("escape", "packing", "Product B", "../outside.exe", hashlib.sha256(b"MZoutside").hexdigest()),
    ]
    _write_manifest(manifest_path, "packing", samples)

    result = audit_manifests([manifest_path])
    by_id = {row["sample_id"]: row for row in result["samples"]}

    assert by_id["changed"]["status"] == "rejected"
    assert "sha256 mismatch" in by_id["changed"]["issues"]
    assert by_id["escape"]["status"] == "invalid_path"
    assert all(row["target_executed"] is False for row in result["samples"])
