"""Read-only target intake gate.

The gate never executes a target and never invokes an analysis tool.  It
verifies that a pinned target exists inside an authorized root, that its
content matches the recorded hash and size limits, and that its authorization
is internally consistent.  A hidden ground-truth label is checked separately
so it cannot leak into an agent-facing payload.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from .hashing import fingerprint_target, target_size
from .models import (
    Authorization,
    DatasetRole,
    IntakeDecision,
    IntakeReason,
    TargetManifest,
)

# src/vulnagent/intake/validator.py -> parents[3] is the repository root.
REPO_ROOT = Path(__file__).resolve().parents[3]

_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_AGGREGATE_BYTES = 2 * 1024 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LabelLeakError(ValueError):
    """Raised when a hidden ground-truth reference reaches an agent payload."""


class TargetIntake(Protocol):
    """Admission boundary used by the research/benchmark workflow."""

    def validate(
        self,
        manifest: TargetManifest,
        *,
        authorized_roots: list[Path] | None = None,
        base_path: Path | None = None,
    ) -> IntakeDecision:
        """Validate one manifest without executing the target."""


def _is_network_path(raw: str) -> bool:
    text = raw.strip()
    if "://" in text:
        return True
    # UNC shares (\\server\share) and POSIX double-slash forms.
    if text.startswith(("\\\\", "//")):
        return True
    # Windows extended-length / device paths bypass normal normalization.
    if text.lower().startswith("\\\\?\\") or text.lower().startswith("\\\\.\\"):
        return True
    return False


class DefaultTargetIntake:
    """Deterministic, side-effect-free implementation of :class:`TargetIntake`."""

    def validate(
        self,
        manifest: TargetManifest,
        *,
        authorized_roots: list[Path] | None = None,
        base_path: Path | None = None,
    ) -> IntakeDecision:
        """Validate one manifest without executing the target."""

        roots = [Path(item).resolve() for item in (authorized_roots or [REPO_ROOT])]
        base = (base_path or REPO_ROOT).resolve()
        issues: list[str] = []
        reasons: list[str] = []

        def fail(reason: IntakeReason, detail: str) -> None:
            reasons.append(reason.value)
            issues.append(detail)

        self._check_fields(manifest, fail)

        raw_path = manifest.target_path
        candidate: Path | None = None
        if _is_network_path(raw_path):
            fail(IntakeReason.NETWORK_PATH, f"network/device path is not allowed: {raw_path}")
        else:
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = (base / candidate).resolve()
            else:
                candidate = candidate.resolve()
            if not any(self._is_within(candidate, root) for root in roots):
                fail(
                    IntakeReason.PATH_ESCAPE,
                    f"target escapes the authorized roots: {candidate}",
                )
            elif not candidate.exists():
                fail(IntakeReason.MISSING_TARGET, f"target does not exist: {candidate}")

        self._check_authorization(manifest.authorization, fail)

        checked_sha = None
        normalized = None
        if candidate is not None and candidate.exists() and any(
            self._is_within(candidate, root) for root in roots
        ):
            normalized = str(candidate)
            self._check_size(candidate, fail)
            checked_sha = fingerprint_target(candidate)
            if checked_sha != manifest.target_sha256:
                fail(
                    IntakeReason.SHA256_MISMATCH,
                    "content hash does not match the pinned manifest "
                    f"(expected {manifest.target_sha256}, got {checked_sha})",
                )

        accepted = not issues
        if accepted:
            reasons.append(IntakeReason.ACCEPTED.value)
        return IntakeDecision(
            sample_id=manifest.sample_id,
            accepted=accepted,
            reason_codes=reasons,
            issues=issues,
            normalized_path=normalized,
            checked_sha256=checked_sha,
            role=manifest.role,
            dynamic_allowed=manifest.dynamic_allowed,
        )

    @staticmethod
    def _is_within(candidate: Path, root: Path) -> bool:
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _check_fields(manifest: TargetManifest, fail) -> None:
        if not manifest.revision.strip():
            fail(IntakeReason.MISSING_REVISION, "revision must be an immutable commit/version")
        if not manifest.license_record.strip():
            fail(IntakeReason.MISSING_LICENSE, "license_record is required")
        if not _HEX64.match(manifest.target_sha256):
            fail(IntakeReason.INVALID_SHA256, "target_sha256 must be 64 lowercase hex digits")

    @staticmethod
    def _check_authorization(auth: Authorization, fail) -> None:
        if not auth.static_read:
            fail(
                IntakeReason.AUTHORIZATION_MISMATCH,
                "static_read must be granted to admit a target",
            )
        if auth.dynamic_run and not auth.statement.strip():
            fail(
                IntakeReason.AUTHORIZATION_MISMATCH,
                "dynamic_run requires a recorded authorization statement",
            )

    @staticmethod
    def _check_size(candidate: Path, fail) -> None:
        if candidate.is_file():
            size = candidate.stat().st_size
            if size <= 0:
                fail(IntakeReason.SIZE_LIMIT, "target file is empty")
            elif size > _MAX_FILE_BYTES:
                fail(IntakeReason.SIZE_LIMIT, f"target file exceeds 256 MiB: {size} bytes")
            return
        for item in candidate.rglob("*"):
            if item.is_file() and item.stat().st_size > _MAX_FILE_BYTES:
                fail(
                    IntakeReason.SIZE_LIMIT,
                    f"file exceeds 256 MiB: {item} ({item.stat().st_size} bytes)",
                )
        aggregate = target_size(candidate)
        if aggregate <= 0:
            fail(IntakeReason.SIZE_LIMIT, "target directory is empty")
        elif aggregate > _MAX_AGGREGATE_BYTES:
            fail(IntakeReason.SIZE_LIMIT, f"target tree exceeds 2 GiB: {aggregate} bytes")


def find_label_leaks(manifest: TargetManifest, texts: dict[str, str]) -> list[str]:
    """Return agent-facing texts that would expose a hidden ground-truth ref.

    Pass the exact strings the agent can see (task metadata, prompt, log
    lines).  The private ``ground_truth_ref`` must never appear in them.
    """

    ref = manifest.ground_truth_ref
    if not ref:
        return []
    return [name for name, text in texts.items() if isinstance(text, str) and ref in text]


def assert_ground_truth_isolated(manifest: TargetManifest, texts: dict[str, str]) -> None:
    """Raise :class:`LabelLeakError` if a hidden reference is exposed."""

    leaks = find_label_leaks(manifest, texts)
    if leaks:
        raise LabelLeakError(
            f"ground_truth_ref for {manifest.sample_id} leaked into: {', '.join(leaks)}"
        )
