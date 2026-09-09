"""Project import for the Source Parser component (member 2).

Turns a *project reference* into a local source tree that
``SourceProjectParser`` can analyze.  Supported origins:

- an existing local directory or single source file  -> used in place
  (origin_type ``path``, VCS detected when a ``.git`` entry exists);
- a local ``.zip`` archive                             -> safely extracted to a
  work directory (origin_type ``zip``; archive-slip entries are rejected);
- a git repository URL                                -> shallow clone into a
  work directory (origin_type ``git``) **only when explicitly requested**
  through ``ProjectInput.metadata["allow_git_clone"]``; remote cloning is
  never performed by default.

Extraction/cloning never follows symlinks out of the destination and never
overwrites paths outside it.  Callers that do not provide ``destination``
receive a managed temporary directory and can remove it again with
``ProjectImporter.cleanup()``.

The importer only materializes input; it never executes project code and
never judges vulnerabilities.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnagent.contracts import ProjectInput

__all__ = [
    "ImportedProject",
    "ProjectImportError",
    "ProjectImporter",
]

_GIT_URL_SCHEMES = ("https://", "http://", "git://", "git+", "ssh://", "file://")
_GIT_SUFFIX = ".git"


class ProjectImportError(Exception):
    """Raised when a project reference cannot be imported safely."""


@dataclass(frozen=True, slots=True)
class ImportedProject:
    """A materialized local project ready for ``SourceProjectParser``."""

    project_path: str
    origin_type: str  # "path" | "zip" | "git"
    origin: str
    vcs: str | None = None
    extracted_to: str | None = None
    notes: tuple[str, ...] = ()


class ProjectImporter:
    """Default project importer: local path, safe zip, gated git clone."""

    def __init__(self) -> None:
        self._managed_dirs: list[Path] = []

    @property
    def managed_dirs(self) -> tuple[Path, ...]:
        """Temporary directories created when no destination was supplied."""
        return tuple(self._managed_dirs)

    async def import_project(
        self,
        request: ProjectInput,
        *,
        destination: Path | str | None = None,
    ) -> ImportedProject:
        """Materialize ``request.project_path`` and describe its origin.

        ``destination`` is used for zip extraction / git clone.  When omitted
        (and needed) a managed temporary directory is created; call
        ``cleanup()`` later to remove everything this importer created.
        """
        reference = Path(request.project_path).expanduser()
        metadata: dict[str, Any] = dict(request.metadata or {})

        if self._looks_like_git_url(str(request.project_path)):
            if not _as_bool(metadata.get("allow_git_clone", False)):
                raise ProjectImportError(
                    "Remote git clone requires ProjectInput.metadata"
                    '["allow_git_clone"]=true; refusing to clone by default.'
                )
            work = await asyncio.to_thread(
                self._clone_git,
                str(request.project_path),
                self._resolve_destination(destination),
                metadata,
            )
            return ImportedProject(
                project_path=str(work),
                origin_type="git",
                origin=str(request.project_path),
                vcs="git",
                extracted_to=str(work),
                notes=("shallow clone",),
            )

        if reference.is_file() and reference.suffix.casefold() == ".zip":
            work = await asyncio.to_thread(
                self._extract_zip,
                reference,
                self._resolve_destination(destination),
                metadata,
            )
            return ImportedProject(
                project_path=str(work),
                origin_type="zip",
                origin=str(request.project_path),
                vcs=None,
                extracted_to=str(work),
            )

        if not reference.exists():
            raise ProjectImportError(
                f"Project path does not exist: {reference}"
            )
        return ImportedProject(
            project_path=str(reference.resolve()),
            origin_type="path",
            origin=str(request.project_path),
            vcs="git" if (reference / ".git").exists() else None,
        )

    def cleanup(self) -> None:
        """Remove managed temporary directories created by this importer."""
        for directory in self._managed_dirs:
            shutil.rmtree(directory, ignore_errors=True)
        self._managed_dirs.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_destination(self, destination: Path | str | None) -> Path:
        if destination is not None:
            root = Path(destination).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            return root
        managed = Path(tempfile.mkdtemp(prefix="vulnagent_import_"))
        self._managed_dirs.append(managed)
        return managed

    def _extract_zip(
        self,
        archive: Path,
        destination: Path,
        metadata: dict[str, Any],
    ) -> Path:
        target = destination / _destination_name(str(archive))
        self._prepare_target(target)
        max_bytes = metadata.get("max_extract_bytes")
        total_bytes = 0
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                entry_path = self._safe_member_path(
                    member.filename, target, archive=archive
                )
                if entry_path is None:  # directory entry
                    continue
                size = member.file_size
                if max_bytes is not None and total_bytes + size > int(max_bytes):
                    raise ProjectImportError(
                        f"Archive exceeds max_extract_bytes={max_bytes}: "
                        f"{archive}"
                    )
                total_bytes += size
                entry_path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, open(
                    entry_path, "wb"
                ) as sink:
                    shutil.copyfileobj(source, sink)
        return target

    @staticmethod
    def _safe_member_path(
        member_name: str,
        target: Path,
        *,
        archive: Path,
    ) -> Path | None:
        """Resolve one archive member inside ``target`` or reject it."""
        normalized = member_name.replace("\\", "/")
        if normalized.endswith("/"):
            return None  # directory entry
        parts = [part for part in normalized.split("/") if part not in ("", ".")]
        if not parts or any(part == ".." for part in parts):
            raise ProjectImportError(
                f"Unsafe archive member in {archive}: {member_name!r}"
            )
        resolved = target.joinpath(*parts).resolve()
        if not resolved.is_relative_to(target.resolve()):
            raise ProjectImportError(
                f"Archive member escapes destination in {archive}: "
                f"{member_name!r}"
            )
        return resolved

    def _clone_git(
        self,
        url: str,
        destination: Path,
        metadata: dict[str, Any],
    ) -> Path:
        git = shutil.which("git")
        if git is None:
            raise ProjectImportError("git executable not found")
        target = destination / _destination_name(url)
        self._prepare_target(target)
        timeout = int(metadata.get("git_clone_timeout_seconds", 90))
        environment = dict(os.environ)
        environment["GIT_TERMINAL_PROMPT"] = "0"
        command = [
            git,
            "clone",
            "--depth",
            "1",
            "--",
            url,
            str(target),
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            shutil.rmtree(target, ignore_errors=True)
            raise ProjectImportError(
                f"git clone failed for {url}: {type(error).__name__}"
            ) from error
        if result.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            raise ProjectImportError(
                f"git clone failed for {url}: "
                f"{(result.stderr or '').strip()[:400]}"
            )
        return target

    @staticmethod
    def _prepare_target(target: Path) -> None:
        if target.exists():
            raise ProjectImportError(
                f"Destination already exists: {target}"
            )
        target.mkdir(parents=True)

    @staticmethod
    def _looks_like_git_url(reference: str) -> bool:
        lowered = reference.casefold()
        if lowered.startswith(_GIT_URL_SCHEMES):
            return True
        return lowered.endswith(_GIT_SUFFIX) and "://" not in lowered and not Path(
            reference
        ).exists()


def _destination_name(origin: str) -> str:
    """Deterministic, unique, short directory name for one import origin."""
    normalized = origin.replace("\\", "/").rstrip("/")
    tail = normalized.rsplit("/", 1)[-1]
    if tail.casefold().endswith(_GIT_SUFFIX):
        tail = tail[: -len(_GIT_SUFFIX)]
    digest = hashlib.sha1(origin.encode("utf-8", "replace")).hexdigest()[:8]
    return f"{_safe_slug(tail)}_{digest}"


def _safe_slug(value: str) -> str:
    """Small deterministic slug for archive stem / git URL."""
    keep = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in value
    )
    return keep.strip("._") or "source"


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).casefold() in {"1", "true", "yes", "on"}
