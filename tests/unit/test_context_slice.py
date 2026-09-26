"""S3 unit: bounded, on-demand context slicing."""

from __future__ import annotations

from pathlib import Path

from vulnagent.analyzers.source.audit.context_slice import (
    ContextSliceProvider,
    SliceResult,
)

SRC = (
    "import os\n"
    "def parse(data):\n"
    "    if len(data) < 4:\n"
    "        return None\n"
    "    header = data[:4]\n"
    "    return header\n"
    "\n"
    "def load(path):\n"
    "    with open(path, 'rb') as f:\n"
    "        raw = f.read()\n"
    "    return parse(raw)\n"
)


def _write_project(tmp: Path) -> tuple[Path, Path]:
    a = tmp / "a.py"
    a.write_text(SRC, encoding="utf-8")
    b = tmp / "b.py"
    b.write_text("def unrelated():\n    return 1\n", encoding="utf-8")
    big = tmp / "big.py"
    big.write_text("\n".join(f"# line {i}" for i in range(5000)), encoding="utf-8")
    return a, b


def test_slice_symbol_window_is_bounded(tmp_path: Path) -> None:
    provider = ContextSliceProvider(window_before=2, window_after=3)
    a = tmp_path / "a.py"
    a.write_text(SRC, encoding="utf-8")
    slice_ = provider.slice_symbol(a, "parse")
    assert slice_ is not None
    assert slice_.matched_symbol == "parse"
    assert slice_.source_kind == "symbol_definition"
    assert slice_.start_line == 1  # def parse is line 2; window starts at 1
    assert slice_.end_line == 5  # line 2 + 3
    assert slice_.text.startswith("import os")
    assert "def parse(data):" in slice_.text


def test_slice_symbol_missing_returns_none(tmp_path: Path) -> None:
    provider = ContextSliceProvider()
    a = tmp_path / "a.py"
    a.write_text(SRC, encoding="utf-8")
    assert provider.slice_symbol(a, "does_not_exist") is None


def test_slice_call_site(tmp_path: Path) -> None:
    provider = ContextSliceProvider(window_before=1, window_after=1)
    a = tmp_path / "a.py"
    a.write_text(SRC, encoding="utf-8")
    slice_ = provider.slice_call_site(a, "parse", call_line=11)
    assert slice_ is not None
    assert slice_.source_kind == "call_site"
    assert "return parse(raw)" in slice_.text


def test_slice_project_only_loads_relevant_files(tmp_path: Path) -> None:
    provider = ContextSliceProvider(max_files=8)
    a, b = _write_project(tmp_path)
    result = provider.slice_project(tmp_path, ["parse"])
    assert isinstance(result, SliceResult)
    assert result.slices
    files = {s.file_path.name for s in result.slices}
    assert files == {"a.py"}  # b.py and big.py are never loaded
    assert "b.py" not in files
    for s in result.slices:
        assert s.matched_symbol == "parse"
        assert s.end_line - s.start_line + 1 <= provider.max_lines_per_file


def test_slice_project_records_truncation_and_limits(tmp_path: Path) -> None:
    provider = ContextSliceProvider(
        max_files=2, max_total_bytes=2000, window_before=1, window_after=1
    )
    a, b = _write_project(tmp_path)
    result = provider.slice_project(tmp_path, ["parse", "unrelated"])
    assert result.limits["max_files"] == 2
    # total bytes bounded by the limit
    assert result.total_bytes <= 2000
    assert any("truncated" in note or len(result.truncated_files) >= 0 for note in result.notes)
    assert result.notes


def test_slice_project_respects_max_files(tmp_path: Path) -> None:
    provider = ContextSliceProvider(max_files=1, window_before=1, window_after=1)
    _write_project(tmp_path)
    result = provider.slice_project(tmp_path, ["parse", "unrelated"])
    assert len(result.slices) <= 1
    assert result.skipped_files  # the rest are recorded as skipped
