"""Course benchmark manifests are complete, balanced and locally resolvable."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRED = {
    "sample_id",
    "path",
    "source",
    "language",
    "target_type",
    "ground_truth",
    "cwe",
    "expected_findings",
    "authorization",
    "run_command",
}
PAIRED_REQUIRED = REQUIRED | {"family_id", "difficulty"}


def _samples(relative_manifest: str) -> list[dict[str, object]]:
    manifest = json.loads((ROOT / relative_manifest).read_text(encoding="utf-8"))
    return manifest["samples"]


def _assert_vulnerable_clean_families(
    samples: list[dict[str, object]],
) -> None:
    families: dict[str, set[object]] = {}
    for item in samples:
        family = str(item["family_id"])
        families.setdefault(family, set()).add(item["ground_truth"])
    assert all(labels == {"vulnerable", "clean"} for labels in families.values())
    assert all(item["difficulty"] in {"basic", "hard"} for item in samples)


def test_source_manifest_has_ten_vulnerable_clean_pairs() -> None:
    samples = _samples("benchmarks/manifest.json")

    assert len(samples) == 20
    assert sum(item["ground_truth"] == "vulnerable" for item in samples) == 10
    assert sum(item["ground_truth"] == "clean" for item in samples) == 10
    assert sum(item["difficulty"] == "hard" for item in samples) == 8
    assert len({item["sample_id"] for item in samples}) == len(samples)
    assert all(PAIRED_REQUIRED <= item.keys() for item in samples)
    assert all((ROOT / str(item["path"])).exists() for item in samples)
    _assert_vulnerable_clean_families(samples)


def test_binary_manifest_has_five_positive_negative_pairs() -> None:
    samples = _samples("benchmarks/binary/manifest.json")

    assert len(samples) == 14
    assert sum(item["ground_truth"] == "vulnerable" for item in samples) == 7
    assert sum(item["ground_truth"] == "clean" for item in samples) == 7
    assert sum(item["difficulty"] == "hard" for item in samples) == 8
    assert len({item["sample_id"] for item in samples}) == len(samples)
    assert all(PAIRED_REQUIRED <= item.keys() for item in samples)
    assert all((ROOT / str(item["path"])).is_file() for item in samples)
    _assert_vulnerable_clean_families(samples)


def test_fuzz_manifest_is_explicitly_authorized() -> None:
    samples = _samples("benchmarks/fuzz/manifest.json")

    assert len(samples) == 1
    assert REQUIRED <= samples[0].keys()
    assert "explicitly allowed" in str(samples[0]["authorization"])
    assert (ROOT / str(samples[0]["path"])).is_file()
