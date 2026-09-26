"""L4: reproduction comparator tests (benchmark/reproducer)."""

from __future__ import annotations

from pathlib import Path

from vulnagent.benchmark.reproducer import ReproductionComparator, ReproductionResult


def _make_runner(vuln_exit: int, fix_exit: int, sanitizer: str = "AddressSanitizer: heap-buffer-overflow"):
    """Return a scripted runner: vulnerable then fixed per replay."""
    calls = {"n": 0}

    def runner(vulnerable_bin, fixed_bin, input_path, args, timeout, replay_count):
        calls["n"] += 1
        if calls["n"] % 2 == 1:
            return vuln_exit, sanitizer if vuln_exit != 0 else ""
        return fix_exit, ""

    return runner


def _input(tmp_path: Path, name: str = "input.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(b"\x00\x01\x02seed")
    return path


class TestReproductionComparator:
    def test_clean_contrast_when_vulnerable_crashes_fixed_clean(self, tmp_path: Path) -> None:
        comparator = ReproductionComparator(runner=_make_runner(vuln_exit=1, fix_exit=0))
        result = comparator.compare(
            vulnerable_bin=Path("vuln.exe"),
            fixed_bin=Path("fix.exe"),
            input_path=_input(tmp_path),
            replay_count=3,
        )
        assert result.vulnerable_crashed is True
        assert result.fixed_crashed is False
        assert result.contrast_clean is True
        assert result.vulnerable_sanitizer == "AddressSanitizer"

    def test_no_clean_contrast_when_both_crash(self, tmp_path: Path) -> None:
        comparator = ReproductionComparator(runner=_make_runner(vuln_exit=1, fix_exit=1))
        result = comparator.compare(
            vulnerable_bin=Path("vuln.exe"),
            fixed_bin=Path("fix.exe"),
            input_path=_input(tmp_path),
            replay_count=3,
        )
        assert result.contrast_clean is False
        assert result.note != "vulnerable crashes every replay, fixed build is clean"

    def test_replay_count_required_positive(self, tmp_path: Path) -> None:
        comparator = ReproductionComparator(runner=_make_runner(1, 0))
        try:
            comparator.compare(
                vulnerable_bin=Path("a"),
                fixed_bin=Path("b"),
                input_path=_input(tmp_path),
                replay_count=0,
            )
            assert False, "expected ValueError"
        except ValueError:
            pass

    def test_negative_exit_treated_as_crash(self, tmp_path: Path) -> None:
        comparator = ReproductionComparator(runner=_make_runner(-1073741819, 0))
        result = comparator.compare(
            vulnerable_bin=Path("a"),
            fixed_bin=Path("b"),
            input_path=_input(tmp_path),
            replay_count=1,
        )
        assert result.vulnerable_crashed is True
        assert result.contrast_clean is True

    def test_result_shape(self, tmp_path: Path) -> None:
        comparator = ReproductionComparator(runner=_make_runner(1, 0))
        result = comparator.compare(
            vulnerable_bin=Path("a"),
            fixed_bin=Path("b"),
            input_path=_input(tmp_path),
            replay_count=2,
        )
        assert isinstance(result, ReproductionResult)
        assert result.replay_count == 2
        assert result.input_sha256  # sha256 of the actual input file
