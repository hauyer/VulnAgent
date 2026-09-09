from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import PythonSourceParser
from vulnagent.contracts import ProjectInput, SourceAnalysisResult


async def analyze(project_path: Path) -> SourceAnalysisResult:
    return await PythonSourceParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(project_path),
        )
    )


@pytest.mark.asyncio
async def test_scans_a_normal_python_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not source\n", encoding="utf-8")
    package = tmp_path / "package"
    package.mkdir()
    (package / "worker.py").write_text("def work():\n    return 1\n", encoding="utf-8")

    result = await analyze(tmp_path)

    assert result.task_id == "task-1"
    assert result.target_id == "target-1"
    assert result.languages == ["Python"]
    assert result.files == ["app.py", "package/worker.py"]
    assert result.metadata["scanned"] is True
    assert result.metadata["file_count"] == 2
    assert result.metadata["parsed_file_count"] == 2
    assert result.metadata["parse_errors"] == []


@pytest.mark.asyncio
async def test_extracts_symbols_dependencies_and_call_graph(tmp_path: Path) -> None:
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

    result = await analyze(tmp_path)

    symbols = {
        symbol["qualified_name"]: (symbol["kind"], symbol["is_async"])
        for symbol in result.symbols
    }
    assert symbols == {
        "main.helper": ("function", False),
        "main.Service": ("class", False),
        "main.Service.run": ("method", False),
        "main.Service.finish": ("method", True),
    }
    assert result.dependencies == ["os", "package.helpers"]
    # Call targets are resolved to project-internal qualified names when a
    # definition exists; external calls keep their syntactic name.
    assert result.call_graph == {
        "main.Service.finish": ["utility"],
        "main.Service.run": ["main.Service.finish", "main.helper"],
        "main.helper": ["os.getcwd"],
    }


@pytest.mark.asyncio
async def test_tolerates_syntax_errors_and_continues(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (tmp_path / "good.py").write_text("def healthy():\n    return True\n", encoding="utf-8")

    result = await analyze(tmp_path)

    assert result.files == ["bad.py", "good.py"]
    assert result.metadata["parsed_file_count"] == 1
    assert result.metadata["error_count"] == 1
    assert result.metadata["parse_errors"][0]["file"] == "bad.py"
    assert result.metadata["parse_errors"][0]["error_type"] == "SyntaxError"
    assert {symbol["qualified_name"] for symbol in result.symbols} == {"good.healthy"}


@pytest.mark.asyncio
async def test_returns_an_empty_result_for_an_empty_project(tmp_path: Path) -> None:
    result = await analyze(tmp_path)

    assert result.languages == []
    assert result.files == []
    assert result.symbols == []
    assert result.dependencies == []
    assert result.call_graph == {}
    assert result.metadata["file_count"] == 0
    assert result.metadata["parsed_file_count"] == 0


@pytest.mark.asyncio
async def test_ignores_generated_and_dependency_directories(tmp_path: Path) -> None:
    ignored_directories = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
    }
    (tmp_path / "visible.py").write_text("def visible():\n    pass\n", encoding="utf-8")
    for directory_name in ignored_directories:
        directory = tmp_path / directory_name
        directory.mkdir()
        (directory / "hidden.py").write_text(
            "def hidden():\n    pass\n", encoding="utf-8"
        )

    result = await analyze(tmp_path)

    assert result.files == ["visible.py"]
    assert {symbol["qualified_name"] for symbol in result.symbols} == {"visible.visible"}
    assert set(result.metadata["ignored_directories"]) == ignored_directories
