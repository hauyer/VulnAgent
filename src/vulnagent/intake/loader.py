"""Load target admission manifests from YAML or JSON.

Accepts both the practice-plan sample naming (``target_type``,
``source_sha256``, ``license``, a string ``authorization`` and a flat
``dynamic_allowed``) and the guide naming (``target_kind``, ``target_sha256``,
``license_record``, a structured ``authorization``).  Unknown keys are ignored
so catalogs can carry extra provenance notes without breaking admission.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import Authorization, DatasetRole, TargetKind, TargetManifest

_MANIFEST_SUFFIXES = (".yaml", ".yml", ".json")


def _build_authorization(raw: Any, static_allowed: bool, dynamic_allowed: bool) -> Authorization:
    if raw is None:
        return Authorization(static_read=static_allowed, dynamic_run=dynamic_allowed)
    if isinstance(raw, str):
        return Authorization(
            statement=raw,
            static_read=static_allowed,
            dynamic_run=dynamic_allowed,
        )
    if isinstance(raw, dict):
        auth = Authorization(**raw)
        # Flat flags only tighten/default; they never silently revoke an
        # explicit structured grant.
        if "static_read" not in raw:
            auth.static_read = static_allowed
        if "dynamic_run" not in raw:
            auth.dynamic_run = dynamic_allowed
        return auth
    raise ValueError("authorization must be a string or an object")


def normalize_manifest_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Map supported catalog key aliases onto the :class:`TargetManifest` shape."""

    def pick(*names: str, default: Any = None) -> Any:
        for name in names:
            if name in data and data[name] is not None:
                return data[name]
        return default

    static_allowed = bool(pick("static_allowed", default=True))
    dynamic_allowed = bool(pick("dynamic_allowed", default=False))
    authorization = _build_authorization(
        pick("authorization", "authorization_record"),
        static_allowed,
        dynamic_allowed,
    )

    normalized = {
        "sample_id": pick("sample_id"),
        "source_name": pick("source_name", "project"),
        "role": pick("role", default=DatasetRole.TRAIN.value),
        "revision": pick("revision"),
        "target_path": pick("target_path", "path"),
        "target_sha256": pick("target_sha256", "source_sha256"),
        "license_record": pick("license_record", "license"),
        "family_id": pick("family_id"),
        "dataset": pick("dataset", default="local"),
        "target_kind": pick("target_kind", "target_type", default=TargetKind.SOURCE.value),
        "language": pick("language"),
        "upstream_uri": pick("upstream_uri", "repository"),
        "fixed_revision": pick("fixed_revision"),
        "authorization": authorization,
        "build_profile": pick("build_profile"),
        "ground_truth_ref": pick("ground_truth_ref"),
        "time_budget_seconds": pick(
            "time_budget_seconds", "budget_seconds", default=300
        ),
        "memory_budget_mb": pick("memory_budget_mb", default=2048),
    }
    missing = [
        name
        for name in (
            "sample_id",
            "source_name",
            "role",
            "revision",
            "target_path",
            "target_sha256",
            "license_record",
        )
        if normalized[name] is None
    ]
    if missing:
        raise ValueError(f"manifest is missing required fields: {', '.join(missing)}")
    return normalized


def _build_manifests(data: dict[str, Any]) -> list[TargetManifest]:
    """Build one manifest, or many when the file is a ``samples`` suite."""

    samples = data.get("samples")
    if isinstance(samples, list):
        defaults = {key: value for key, value in data.items() if key != "samples"}
        records = [{**defaults, **record} for record in samples]
    else:
        records = [data]
    return [TargetManifest(**normalize_manifest_dict(record)) for record in records]


def load_suite(path: Path) -> list[TargetManifest]:
    """Load a single manifest or a whole ``samples`` suite from one file."""

    source = Path(path)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"manifest must be an object: {source}")
    return _build_manifests(data)


def load_manifest(path: Path) -> TargetManifest:
    """Load and validate one target manifest from YAML or JSON."""

    return load_suite(path)[0]


def load_manifest_dir(directory: Path) -> list[TargetManifest]:
    """Load every manifest/suite in a directory, rejecting duplicate ids."""

    root = Path(directory)
    manifests: list[TargetManifest] = []
    seen: set[str] = set()
    for source in sorted(root.rglob("*")):
        if not source.is_file() or source.suffix.lower() not in _MANIFEST_SUFFIXES:
            continue
        if source.name.startswith("_") or "TEMPLATE" in source.name.upper():
            continue
        for manifest in load_suite(source):
            if manifest.sample_id in seen:
                raise ValueError(f"duplicate sample_id across catalog: {manifest.sample_id}")
            seen.add(manifest.sample_id)
            manifests.append(manifest)
    return manifests
