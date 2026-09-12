"""Normalized C/C++/Go AST and CFG coverage."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import ProjectInput


async def _analyze(path: Path):
    return await SourceProjectParser().analyze(
        ProjectInput(task_id="task-native", target_id="target-native", project_path=str(path))
    )


@pytest.mark.asyncio
async def test_c_parser_exports_ast_cfg_symbols_dependencies_and_facts(tmp_path: Path) -> None:
    source = tmp_path / "copy.c"
    source.write_text(
        """#include <string.h>
int copy_value(const char *input, int n) {
    char buffer[16];
    if (n > 0) {
        memcpy(buffer, input, n);
    }
    return buffer[0];
}
""",
        encoding="utf-8",
    )

    result = await _analyze(source)
    native = result.metadata["native_analysis"]["files"]["copy.c"]
    function = native["functions"][0]

    assert result.languages == ["c"]
    assert result.dependencies == ["string.h"]
    assert function["qualified_name"] == "copy.copy_value"
    assert [item["name"] for item in function["parameters"]] == ["input", "n"]
    assert native["ast"]["nodes"][0]["node_type"] == "translation_unit"
    assert {item["node_type"] for item in function["cfg"]["nodes"]} >= {
        "entry",
        "condition",
        "exit",
    }
    assert function["cfg"]["edges"]
    assert "true" in {item["kind"] for item in function["cfg"]["edges"]}
    assert "false" in {item["kind"] for item in function["cfg"]["edges"]}
    assert any(item["kind"] == "call" and item["callee"] == "memcpy" for item in function["facts"])
    assert any(item["kind"] == "array_declaration" for item in function["facts"])


@pytest.mark.asyncio
async def test_go_parser_exports_function_cfg_import_and_index_fact(tmp_path: Path) -> None:
    source = tmp_path / "handler.go"
    source.write_text(
        """package demo

import "net/http"

func handler(w http.ResponseWriter, r *http.Request, index int) byte {
    data := []byte("safe")
    if index >= 0 && index < len(data) {
        return data[index]
    }
    return 0
}
""",
        encoding="utf-8",
    )

    result = await _analyze(source)
    native = result.metadata["native_analysis"]["files"]["handler.go"]
    function = native["functions"][0]

    assert result.languages == ["go"]
    assert result.dependencies == ["net/http"]
    assert function["name"] == "handler"
    assert {item["name"] for item in function["parameters"]} >= {"w", "r", "index"}
    assert any(item["kind"] == "condition" for item in function["facts"])
    assert any(item["kind"] == "index" and item["index"] == "index" for item in function["facts"])
    assert function["cfg"]["nodes"]


@pytest.mark.asyncio
async def test_recoverable_native_syntax_error_is_explicit(tmp_path: Path) -> None:
    source = tmp_path / "broken.cpp"
    source.write_text("int broken( { return 1; }", encoding="utf-8")

    result = await _analyze(source)

    assert result.metadata["parsed_file_count"] == 1
    assert result.metadata["error_count"] == 1
    assert result.metadata["parse_errors"][0]["error_type"] == "TreeSitterSyntaxError"
    assert result.metadata["native_analysis"]["files"]["broken.cpp"]["has_syntax_error"] is True
