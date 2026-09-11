"""Audit provenance and readiness of packed/obfuscated course samples.

The intake gate never executes a target and never invokes an unpacker or
decompiler.  It exists to prevent placeholder, unlicensed, missing, or
silently changed files from entering the stricter protected-binary benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_KINDS = {"packing", "obfuscation"}
_STATUSES = {"pending_user_supplied", "materialized"}
_REQUIRED_SAMPLE_FIELDS = {
    "sample_id",
    "acquisition_status",
    "qualification",
    "software",
    "protection",
    "provenance",
    "authorization",
    "local_path",
    "sha256",
    "file_format",
    "architecture",
    "expected_observations",
}
_MAX_SAMPLE_BYTES = 256 * 1024 * 1024


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate one protected-sample intake manifest."""

    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("protected sample manifest must be an object")
    kind = value.get("protection_kind")
    if kind not in _KINDS:
        raise ValueError(f"invalid protection_kind: {kind}")
    samples = value.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("protected sample manifest must contain samples")

    identifiers: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"sample {index} must be an object")
        missing = sorted(_REQUIRED_SAMPLE_FIELDS.difference(sample))
        if missing:
            raise ValueError(f"sample {index} is missing fields: {', '.join(missing)}")
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in identifiers:
            raise ValueError(f"invalid or duplicate sample_id: {sample_id}")
        identifiers.add(sample_id)
        if sample.get("acquisition_status") not in _STATUSES:
            raise ValueError(f"sample {sample_id} has invalid acquisition_status")
        if sample.get("qualification") != "strict_closed_source":
            raise ValueError(f"sample {sample_id} must use strict_closed_source qualification")
        _validate_nested_objects(sample_id, sample, str(kind))
    return value


def _validate_nested_objects(
    sample_id: str,
    sample: dict[str, Any],
    manifest_kind: str,
) -> None:
    software = sample.get("software")
    protection = sample.get("protection")
    provenance = sample.get("provenance")
    authorization = sample.get("authorization")
    if not all(isinstance(item, dict) for item in (software, protection, provenance, authorization)):
        raise ValueError(f"sample {sample_id} has invalid nested records")
    if protection.get("kind") != manifest_kind:
        raise ValueError(f"sample {sample_id} protection kind does not match manifest")
    if authorization.get("dynamic_execution") is not False:
        raise ValueError(f"sample {sample_id} must default dynamic_execution to false")
    if sample["acquisition_status"] != "materialized":
        return

    required_values = {
        "software.name": software.get("name"),
        "software.version": software.get("version"),
        "protection.product": protection.get("product"),
        "provenance.source_uri": provenance.get("source_uri"),
        "provenance.license_or_terms": provenance.get("license_or_terms"),
        "authorization.statement": authorization.get("statement"),
        "local_path": sample.get("local_path"),
        "file_format": sample.get("file_format"),
        "architecture": sample.get("architecture"),
    }
    missing = [name for name, field in required_values.items() if not isinstance(field, str) or not field.strip()]
    if missing:
        raise ValueError(f"materialized sample {sample_id} lacks: {', '.join(missing)}")
    if software.get("closed_source") is not True:
        raise ValueError(f"materialized sample {sample_id} is not recorded as closed source")
    if authorization.get("static_analysis") is not True:
        raise ValueError(f"materialized sample {sample_id} lacks static-analysis authorization")
    digest = sample.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError(f"materialized sample {sample_id} has invalid sha256")
    observations = sample.get("expected_observations")
    if not isinstance(observations, list) or not observations or not all(
        isinstance(item, str) and item.strip() for item in observations
    ):
        raise ValueError(f"materialized sample {sample_id} needs expected observations")


def _fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_format(path: Path) -> str | None:
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic[:2] == b"MZ":
        return "PE"
    if magic == b"\x7fELF":
        return "ELF"
    return None


def _audit_sample(
    sample: dict[str, Any],
    *,
    manifest_path: Path,
) -> dict[str, Any]:
    base = {
        "sample_id": sample["sample_id"],
        "protection_kind": sample["protection"]["kind"],
        "qualification": sample["qualification"],
        "target_executed": False,
        "tool_transform_executed": False,
        "dynamic_execution_authorized": False,
    }
    if sample["acquisition_status"] == "pending_user_supplied":
        return {
            **base,
            "status": "pending_user_supplied",
            "intake_ready": False,
            "issues": ["authorized sample file and provenance record are not supplied"],
        }

    materials_root = (manifest_path.parent / "materials").resolve()
    raw_path = Path(str(sample["local_path"]))
    if raw_path.is_absolute():
        return {**base, "status": "invalid_path", "intake_ready": False, "issues": ["local_path must be relative"]}
    candidate = (manifest_path.parent / raw_path).resolve()
    if not candidate.is_relative_to(materials_root):
        return {**base, "status": "invalid_path", "intake_ready": False, "issues": ["sample must remain under the manifest materials directory"]}
    if not candidate.is_file():
        return {**base, "status": "missing_file", "intake_ready": False, "issues": ["sample file does not exist"]}
    size = candidate.stat().st_size
    if size <= 0 or size > _MAX_SAMPLE_BYTES:
        return {**base, "status": "invalid_size", "intake_ready": False, "issues": ["sample size is empty or exceeds 256 MiB"]}
    digest = _fingerprint(candidate)
    observed_format = _file_format(candidate)
    issues: list[str] = []
    if digest != sample["sha256"]:
        issues.append("sha256 mismatch")
    if observed_format is None:
        issues.append("unsupported or unrecognized binary format")
    elif str(sample["file_format"]).upper() != observed_format:
        issues.append("declared file_format does not match file magic")
    return {
        **base,
        "status": "intake_ready" if not issues else "rejected",
        "intake_ready": not issues,
        "issues": issues,
        "software_name": sample["software"]["name"],
        "software_version": sample["software"]["version"],
        "protector_product": sample["protection"]["product"],
        "file_size": size,
        "observed_sha256": digest,
        "observed_file_format": observed_format,
    }


def audit_manifests(paths: list[Path]) -> dict[str, Any]:
    """Audit manifests and calculate strict two-per-kind readiness."""

    rows: list[dict[str, Any]] = []
    manifest_records: list[dict[str, Any]] = []
    global_ids: set[str] = set()
    for raw_path in paths:
        path = raw_path.resolve()
        manifest = load_manifest(path)
        manifest_records.append(
            {
                "path": str(path),
                "sha256": _fingerprint(path),
                "suite_id": manifest.get("suite_id"),
                "protection_kind": manifest["protection_kind"],
            }
        )
        for sample in manifest["samples"]:
            if sample["sample_id"] in global_ids:
                raise ValueError(f"duplicate sample_id across manifests: {sample['sample_id']}")
            global_ids.add(sample["sample_id"])
            rows.append(_audit_sample(sample, manifest_path=path))

    ready_identities: dict[str, set[str]] = {kind: set() for kind in _KINDS}
    for row in rows:
        if row["intake_ready"]:
            ready_identities[row["protection_kind"]].add(str(row["software_name"]).casefold())
    ready_counts = {kind: len(names) for kind, names in sorted(ready_identities.items())}
    strict_met = all(ready_counts[kind] >= 2 for kind in _KINDS)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "operation": "read_only_provenance_and_hash_intake",
        "target_execution": False,
        "tool_transform_execution": False,
        "strict_requirement_met": strict_met,
        "required_distinct_software_per_kind": 2,
        "ready_distinct_software": ready_counts,
        "manifests": manifest_records,
        "samples": rows,
    }


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    result = audit_manifests(args.manifest)
    _write_json_atomic(args.output_dir.resolve() / "readiness.json", result)
    print(
        "protected sample intake: packing={packing} obfuscation={obfuscation} strict={strict}".format(
            **result["ready_distinct_software"],
            strict=str(result["strict_requirement_met"]).lower(),
        )
    )
    return 2 if args.require_complete and not result["strict_requirement_met"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
