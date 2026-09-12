"""SourceProjectParser behavior tests (V0.3 real source chain)."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import (
    PythonSourceParser,
    SourceProjectParser,
)
from vulnagent.contracts import ProjectInput, SourceAnalysisResult


async def analyze(project_path: Path, metadata: dict | None = None) -> SourceAnalysisResult:
    return await SourceProjectParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(project_path),
            metadata=metadata or {},
        )
    )


@pytest.mark.asyncio
async def test_indexes_a_python_only_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n\ndef main():\n    return os.getcwd()\n",
        encoding="utf-8",
    )
    package = tmp_path / "package"
    package.mkdir()
    (package / "worker.py").write_text(
        "def work():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "notes.txt").write_text("not source\n", encoding="utf-8")

    result = await analyze(tmp_path)

    assert result.languages == ["python"]
    assert result.files == ["app.py", "package/worker.py"]
    assert result.metadata["parser"] == "source_project"
    assert result.metadata["language_counts"] == {"python": 2}
    assert result.metadata["parsed_languages"] == ["python"]
    assert result.metadata["unsupported_languages"] == []
    assert result.metadata["parsed_file_count"] == 2
    assert result.metadata["other_file_count"] == 1
    assert result.metadata["parse_errors"] == []
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "app.main",
        "package.worker.work",
    }
    assert result.dependencies == ["os"]


@pytest.mark.asyncio
async def test_mixed_project_parses_python_c_and_cpp_without_crashing(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (tmp_path / "util.c").write_text("#include <stdio.h>\nint main(){return 0;}\n")
    (tmp_path / "impl.cpp").write_text("int f(){return 1;}\n")

    result = await analyze(tmp_path)

    assert result.languages == ["c", "cpp", "python"]
    assert set(result.files) == {"main.py", "util.c", "impl.cpp"}
    assert result.metadata["language_counts"] == {"c": 1, "cpp": 1, "python": 1}
    assert result.metadata["parsed_languages"] == ["c", "cpp", "python"]
    assert result.metadata["unsupported_languages"] == []
    assert result.metadata["parsed_file_count"] == 3
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "main.run",
        "util.main",
        "impl.f",
    }
    assert result.metadata["native_analysis"]["engine"] == "tree_sitter"
    assert set(result.metadata["native_analysis"]["files"]) == {"impl.cpp", "util.c"}
    assert result.metadata["error_count"] == 0


@pytest.mark.asyncio
async def test_single_python_file_input(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def main():\n    return 1\n", encoding="utf-8")

    result = await analyze(source)

    assert result.languages == ["python"]
    assert result.files == ["app.py"]
    assert result.metadata["language_counts"] == {"python": 1}
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "app.main"
    }


@pytest.mark.asyncio
async def test_single_c_source_file_is_structurally_parsed(tmp_path: Path) -> None:
    source = tmp_path / "prog.c"
    source.write_text("int main(){return 0;}\n")

    result = await analyze(source)

    assert result.languages == ["c"]
    assert result.files == ["prog.c"]
    assert result.metadata["unsupported_languages"] == []
    assert result.metadata["parsed_languages"] == ["c"]
    assert {symbol["qualified_name"] for symbol in result.symbols} == {"prog.main"}
    assert result.dependencies == []


@pytest.mark.asyncio
async def test_syntax_error_is_recorded_and_other_files_continue(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (tmp_path / "good.py").write_text("def healthy():\n    return True\n", encoding="utf-8")

    result = await analyze(tmp_path)

    assert result.files == ["bad.py", "good.py"]
    assert result.metadata["parsed_file_count"] == 1
    assert result.metadata["error_count"] == 1
    assert result.metadata["parse_errors"][0]["file"] == "bad.py"
    assert result.metadata["parse_errors"][0]["error_type"] == "SyntaxError"
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "good.healthy"
    }


@pytest.mark.asyncio
async def test_oversized_files_are_skipped_and_counted(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("def f():\n    return 'x' * 100\n")
    (tmp_path / "small.py").write_text("x = 1\n")

    result = await analyze(tmp_path, {"max_file_bytes": 16})

    assert result.files == ["small.py"]
    assert result.metadata["skipped_oversized_files"] == 1
    assert result.metadata["file_count"] == 1
    assert result.metadata["parsed_file_count"] == 1


@pytest.mark.asyncio
async def test_invalid_max_file_bytes_falls_back_to_default(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n")

    result = await analyze(tmp_path, {"max_file_bytes": "not-a-number"})

    assert result.metadata["max_file_bytes"] == 1_000_000
    assert result.files == ["ok.py"]


@pytest.mark.asyncio
async def test_empty_project_returns_empty_result(tmp_path: Path) -> None:
    result = await analyze(tmp_path)

    assert result.languages == []
    assert result.files == []
    assert result.symbols == []
    assert result.dependencies == []
    assert result.call_graph == {}
    assert result.metadata["scanned"] is True
    assert result.metadata["file_count"] == 0
    assert result.metadata["parsed_file_count"] == 0
    assert result.metadata["error_count"] == 0


@pytest.mark.asyncio
async def test_missing_path_returns_recorded_error(tmp_path: Path) -> None:
    result = await analyze(tmp_path / "does-not-exist")

    assert result.languages == []
    assert result.metadata["scanned"] is False
    assert result.metadata["error_count"] == 1
    assert result.metadata["parse_errors"][0]["error_type"] == "PathNotFoundError"


@pytest.mark.asyncio
async def test_extended_ignored_directories_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("def real():\n    pass\n", encoding="utf-8")
    for directory_name in (".idea", "target", "htmlcov", ".pytest_cache"):
        directory = tmp_path / directory_name
        directory.mkdir()
        (directory / "hidden.py").write_text(
            "def hidden():\n    pass\n", encoding="utf-8"
        )

    result = await analyze(tmp_path)

    assert result.files == ["real.py"]
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "real.real"
    }
    assert ".idea" in result.metadata["ignored_directories"]
    assert "target" in result.metadata["ignored_directories"]


@pytest.mark.asyncio
async def test_parity_with_python_parser_for_python_only_trees(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        """import os
from package.helpers import utility

def helper():
    return os.getcwd()

class Service:
    def run(self):
        helper()
        self.finish()

    async def finish(self):
        return utility()
""",
        encoding="utf-8",
    )
    package = tmp_path / "package"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text(
        "def utility():\n    return 1\n", encoding="utf-8"
    )

    project_result = await analyze(tmp_path)
    python_result = await PythonSourceParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )

    assert project_result.files == python_result.files
    assert project_result.symbols == python_result.symbols
    assert project_result.dependencies == python_result.dependencies
    assert project_result.call_graph == python_result.call_graph
    # language spelling differs between the legacy and project parser.
    assert project_result.languages == ["python"]
    assert python_result.languages == ["Python"]
