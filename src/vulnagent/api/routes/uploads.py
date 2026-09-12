"""Bounded local sample upload endpoint for the browser demo."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

from vulnagent.contracts import TargetType


router = APIRouter(prefix="/uploads", tags=["uploads"])

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
UPLOAD_ROOT = REPOSITORY_ROOT / "artifacts" / "uploads"
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

_SOURCE_LANGUAGES = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".py": "python",
    ".go": "go",
}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class UploadResult(BaseModel):
    """Public, secret-free metadata returned after a bounded upload."""

    original_name: str
    stored_path: str
    target_type: TargetType
    language: str | None = None
    file_format: str | None = None
    size_bytes: int
    sha256: str


def _safe_filename(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    basename = Path(normalized).name.strip()
    original = Path(basename)
    suffix = _SAFE_NAME.sub("", original.suffix.casefold())[:20]
    stem = _SAFE_NAME.sub("_", original.stem).strip("._") or "sample"
    safe = f"{stem[: max(1, 180 - len(suffix))]}{suffix}"
    if not basename or safe in {".", ".."}:
        raise HTTPException(status_code=400, detail="filename is invalid")
    return safe


def _classify(payload: bytes, target_type: TargetType, filename: str) -> tuple[str | None, str | None]:
    suffix = Path(filename).suffix.casefold()
    if target_type is TargetType.SOURCE:
        language = _SOURCE_LANGUAGES.get(suffix)
        if language is None:
            raise HTTPException(
                status_code=415,
                detail="source uploads support C, C++, Go, and Python text files",
            )
        if b"\x00" in payload[:4096]:
            raise HTTPException(status_code=415, detail="source upload appears to be binary")
        return language, None

    if target_type is not TargetType.BINARY:
        raise HTTPException(
            status_code=400,
            detail="browser uploads support only source or binary targets",
        )
    if payload.startswith(b"\x7fELF"):
        return None, "ELF"
    if payload.startswith(b"MZ"):
        return None, "PE"
    if payload.startswith(b"dex\n"):
        return None, "DEX"
    if payload.startswith(b"PK\x03\x04") and suffix == ".apk":
        return None, "APK"
    raise HTTPException(status_code=415, detail="binary upload must contain an ELF, PE, DEX or APK header")


@router.post("", response_model=UploadResult, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    request: Request,
    filename: str = Query(min_length=1, max_length=255),
    target_type: TargetType = Query(),
) -> UploadResult:
    """Store one explicitly selected source/ELF/PE/DEX/APK sample without executing it."""

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="upload exceeds the 16 MiB limit")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid Content-Length header") from exc

    payload = bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="upload exceeds the 16 MiB limit")
    if not payload:
        raise HTTPException(status_code=400, detail="upload body must not be empty")

    safe_name = _safe_filename(filename)
    language, file_format = _classify(bytes(payload), target_type, safe_name)
    upload_id = uuid4().hex
    destination_dir = (UPLOAD_ROOT / upload_id).resolve()
    resolved_root = UPLOAD_ROOT.resolve()
    if not destination_dir.is_relative_to(resolved_root):
        raise HTTPException(status_code=400, detail="invalid upload destination")
    destination_dir.mkdir(parents=True, exist_ok=False)
    destination = destination_dir / safe_name
    destination.write_bytes(payload)

    try:
        stored_path = destination.relative_to(REPOSITORY_ROOT.resolve()).as_posix()
    except ValueError:
        # Test or embedded applications may deliberately inject an external upload root.
        stored_path = str(destination)
    return UploadResult(
        original_name=filename,
        stored_path=stored_path,
        target_type=target_type,
        language=language,
        file_format=file_format,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
