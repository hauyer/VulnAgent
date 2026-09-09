"""Structure-index tests: class bases, decorators, parameters, entry points."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import (
    PythonSourceParser,
    SourceProjectParser,
)
from vulnagent.contracts import ProjectInput

LINES = [
    "from typing import Optional",
    "",
    "@route('/run')",
    "def run(",
    "    value: str,",
    "    flag: bool = False,",
    "    *args,",
    "    retries: int = 3,",
    "    **kwargs,",
    ") -> Optional[str]:",
    "    return value",
    "",
    "class Service(BaseHandler):",
    "    @staticmethod",
    "    def __init__(self, name: str) -> None:",
    "        self.name = name",
    "",
    "if __name__ == '__main__':",
    "    run('x')",
]

MAIN_LINE = LINES.index("if __name__ == '__main__':") + 1


def write_lines(tmp_path: Path, lines: list[str]) -> Path:
    source = tmp_path / "app.py"
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return source


async def parse(tmp_path: Path) -> object:
    return await SourceProjectParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )


def symbol(result, qualified_name: str) -> dict:
    return next(
        symbol
        for symbol in result.symbols
        if symbol["qualified_name"] == qualified_name
    )


@pytest.mark.asyncio
async def test_class_symbols_carry_bases_and_decorators(tmp_path: Path) -> None:
    write_lines(tmp_path, LINES)

    result = await parse(tmp_path)

    service = symbol(result, "app.Service")
    assert service["kind"] == "class"
    assert service["bases"] == ["BaseHandler"]
    assert service["decorators"] == []


@pytest.mark.asyncio
async def test_function_symbols_carry_decorators_parameters_and_return_type(
    tmp_path: Path,
) -> None:
    write_lines(tmp_path, LINES)

    result = await parse(tmp_path)
    run_symbol = symbol(result, "app.run")

    assert run_symbol["decorators"] == ["route('/run')"]
    assert run_symbol["parameters"] == [
        {
            "name": "value",
            "kind": "positional_or_keyword",
            "has_default": False,
            "annotation": "str",
        },
        {
            "name": "flag",
            "kind": "positional_or_keyword",
            "has_default": True,
            "annotation": "bool",
        },
        {
            "name": "args",
            "kind": "vararg",
            "has_default": False,
            "annotation": None,
        },
        {
            "name": "retries",
            "kind": "keyword_only",
            "has_default": True,
            "annotation": "int",
        },
        {
            "name": "kwargs",
            "kind": "kwarg",
            "has_default": False,
            "annotation": None,
        },
    ]
    assert run_symbol["return_annotation"] == "Optional[str]"

    init_symbol = symbol(result, "app.Service.__init__")
    assert init_symbol["parameters"] == [
        {
            "name": "self",
            "kind": "positional_or_keyword",
            "has_default": False,
            "annotation": None,
        },
        {
            "name": "name",
            "kind": "positional_or_keyword",
            "has_default": False,
            "annotation": "str",
        },
    ]
    assert init_symbol["return_annotation"] == "None"


@pytest.mark.asyncio
async def test_main_guard_is_reported_as_entry_point(tmp_path: Path) -> None:
    (tmp_path / "cli.py").write_text(
        "def main():\n    return 1\n\n"
        "if __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    (tmp_path / "lib.py").write_text(
        "def helper():\n    return 2\n", encoding="utf-8"
    )

    result = await parse(tmp_path)

    assert result.metadata["entry_points"] == [
        {"file": "cli.py", "line": 4}
    ]
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "cli.main",
        "lib.helper",
    }


@pytest.mark.asyncio
async def test_structure_index_is_identical_across_parsers(tmp_path: Path) -> None:
    write_lines(tmp_path, LINES)

    project_result = await parse(tmp_path)
    python_result = await PythonSourceParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )

    assert project_result.symbols == python_result.symbols
    assert (
        project_result.metadata["entry_points"]
        == python_result.metadata["entry_points"]
    )
