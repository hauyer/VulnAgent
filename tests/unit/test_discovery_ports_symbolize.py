"""S2 unit: Windows ASan frame symbolization in the discovery ports.

The harness tooling resolves ``(exe+0xRVA)`` crash frames with
llvm-symbolizer so candidates can carry a location derived only from the
observed crash stack.  These tests run against the actually-built wasm3
target when present and skip otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.benchmark.discovery_ports import (
    _pe_image_base,
    symbolize_asan_frames,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXE = (
    REPO_ROOT
    / "third_party"
    / "wasm3-vuln"
    / "wasm3_asan.exe"
)

pytestmark = pytest.mark.skipif(
    not EXE.is_file(),
    reason="wasm3 vulnerable ASan build not present",
)


def test_pe_image_base_of_built_target() -> None:
    base = _pe_image_base(EXE)
    assert base >= 0x140000000  # typical clang x64 image base


def test_symbolize_asan_frames_resolves_real_frames() -> None:
    stderr = (
        "==29864==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "#0 0x7ff6503055d8 (D:\\proj\\wasm3_asan.exe+0x155d8)\n"
        "#1 0x7ff65030562c (D:\\proj\\wasm3_asan.exe+0x1562c)\n"
    )
    frames = symbolize_asan_frames(stderr, EXE)
    # op_Const64 lives in m3_exec.h in the vulnerable revision; the exact line
    # may shift between rebuilds, but the file must resolve.
    assert frames
    assert all(f.count(":") == 1 for f in frames)
    assert any(f.startswith("m3_exec.h:") for f in frames)


def test_symbolize_ignores_non_pe_frames() -> None:
    frames = symbolize_asan_frames("no crash frames here\n", EXE)
    assert frames == ()
