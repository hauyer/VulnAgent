"""Download portable reverse-engineering tools (UPX, radare2) into tools/.

Used for local study of the Binary Obfuscation / Logic module. These tools are
NOT imported by VulnAgent analyzers: the module only consumes BinaryAnalysisResult,
and external tools belong behind the Adapter boundary.

Run from the repo root:

    python scripts/fetch_binary_tools.py

Idempotent: skips a tool when its archive or extracted directory already exists.
"""
from __future__ import annotations

import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"

# archive name -> (download URL, extract subdir)
TARGETS: dict[str, tuple[str, str]] = {
    "upx-5.2.1-win64.zip": (
        "https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip",
        "upx",
    ),
    "radare2-6.2.2-w64.zip": (
        "https://github.com/radareorg/radare2/releases/download/6.2.2/radare2-6.2.2-w64.zip",
        "radare2",
    ),
}


def _download(url: str, dest: Path) -> None:
    print(f"downloading {url}", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "vulnagent-fetch/0.1"})
    with urllib.request.urlopen(req, timeout=180) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            fh.write(chunk)
    print(f"  saved {dest.name} ({dest.stat().st_size} bytes)", flush=True)


def _extract(archive: Path, dest: Path) -> None:
    print(f"extracting {archive.name} -> {dest}", flush=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)
    print("  done", flush=True)


def main() -> int:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    for archive_name, (url, subdir) in TARGETS.items():
        archive = TOOLS_DIR / archive_name
        if not archive.exists():
            _download(url, archive)
        dest = TOOLS_DIR / subdir
        if not dest.exists() or not any(dest.iterdir()):
            _extract(archive, dest)
    print("completed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
