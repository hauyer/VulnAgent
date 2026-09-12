"""Defensive native-source rule and taint-path coverage."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.audit import MultiLanguageSourceAuditor, NativeSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import ProjectInput, VulnerabilityStatus


async def _audit(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    parsed = await SourceProjectParser().analyze(
        ProjectInput(task_id="task-audit", target_id="target-audit", project_path=str(path))
    )
    return parsed, await NativeSourceAuditor().audit(parsed)


@pytest.mark.asyncio
async def test_api_parameter_taint_reaches_unbounded_copy(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "copy.c",
        """#include <string.h>
void copy_name(const char *input) {
    char name[16];
    strcpy(name, input);
}
""",
    )

    by_type = {item.vulnerability_type: item for item in findings}
    finding = by_type["buffer_overflow"]
    assert finding.status is VulnerabilityStatus.CANDIDATE
    assert finding.location is not None
    assert finding.location.file_path == "copy.c"
    assert finding.location.function_name == "copy.copy_name"
    assert finding.location.line_start == 4
    assert finding.severity == "HIGH"
    assert finding.metadata["sink"] == "strcpy"
    assert finding.metadata["risk_subtype"] == "stack_buffer_overflow"
    assert finding.metadata["taint_path"][0].startswith("source:api_parameter:input")
    assert finding.metadata["cfg_path"]
    assert finding.metadata["cfg_path"][-1]["line"] == 4
    assert "input_validation_missing" in by_type
    assert "exploit" not in str(finding.model_dump()).casefold()


@pytest.mark.asyncio
async def test_null_resource_and_access_control_candidates(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "service.c",
        """#include <stdio.h>
int read_value(int *value) { return *value; }
void load_file(const char *path) { FILE *file = fopen(path, "r"); }
void update_handler(void *cfg) { UpdateConfig(cfg); }
void admin_handler(void) { Shutdown(); }
""",
    )

    types = {item.vulnerability_type for item in findings}
    assert "null_pointer_dereference" in types
    assert "resource_leak" in types
    assert "configuration_authorization_missing" in types
    assert "interface_access_control_missing" in types
    assert all(item.status is VulnerabilityStatus.CANDIDATE for item in findings)


@pytest.mark.asyncio
async def test_network_buffer_source_propagates_through_assignment(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "network.c",
        """#include <string.h>
#include <sys/socket.h>
void handle(int fd) {
    char incoming[64];
    char alias[64];
    recv(fd, incoming, 64, 0);
    char *value = incoming;
    strcpy(alias, value);
}
""",
    )

    finding = next(item for item in findings if item.vulnerability_type == "buffer_overflow")
    path = finding.metadata["taint_path"]
    assert any("input_call:recv" in step for step in path)
    assert any("assignment:value" in step for step in path)
    assert path[-1].startswith("sink:strcpy")


@pytest.mark.asyncio
async def test_memcpy_literal_mismatch_is_reported(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "mismatch.cpp",
        """#include <cstring>
void copy_fixed(const char *input) {
    char destination[8];
    memcpy(destination, input, 32);
}
""",
    )

    finding = next(item for item in findings if item.vulnerability_type == "buffer_overflow")
    assert finding.metadata["destination_capacity"] == 8
    assert finding.metadata["copy_length"] == "32"


@pytest.mark.asyncio
async def test_checked_memcpy_length_is_not_reported(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "checked.c",
        """#include <string.h>
void checked(const char *input, unsigned long n) {
    char destination[16];
    if (n > sizeof(destination)) return;
    memcpy(destination, input, n);
}
""",
    )

    assert not any(
        item.metadata.get("sink") == "memcpy" and item.vulnerability_type == "buffer_overflow"
        for item in findings
    )


@pytest.mark.asyncio
async def test_tainted_allocation_arithmetic_and_index_are_candidates(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "sizes.c",
        """#include <stdlib.h>
int inspect(unsigned long count, int index) {
    char *buffer = malloc(count * 8);
    return buffer[index + 1];
}
""",
    )

    types = [item.vulnerability_type for item in findings]
    assert "integer_overflow" in types
    assert "array_out_of_bounds" in types
    assert "input_validation_missing" in types
    assert all(item.status is VulnerabilityStatus.CANDIDATE for item in findings)


@pytest.mark.asyncio
async def test_calloc_implicit_product_is_checked_for_integer_overflow(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "calloc.c",
        """#include <stdlib.h>
void *allocate(unsigned long count) {
    return calloc(count, sizeof(int));
}
""",
    )

    finding = next(item for item in findings if item.vulnerability_type == "integer_overflow")
    assert finding.metadata["sink"] == "calloc"


@pytest.mark.asyncio
async def test_go_api_parameter_flows_to_make_size_and_slice_index(tmp_path: Path) -> None:
    _, findings = await _audit(
        tmp_path,
        "sizes.go",
        """package demo

func build(count int, index int) byte {
    data := make([]byte, count * 2)
    return data[index]
}
""",
    )

    assert {item.vulnerability_type for item in findings} >= {
        "integer_overflow",
        "array_out_of_bounds",
    }
    assert {item.metadata["language"] for item in findings} == {"go"}


@pytest.mark.asyncio
async def test_composite_auditor_keeps_python_and_native_producers(tmp_path: Path) -> None:
    (tmp_path / "web.py").write_text(
        """from flask import Flask, request
app = Flask(__name__)
@app.get('/run')
def run():
    return eval(request.args.get('value'))
""",
        encoding="utf-8",
    )
    (tmp_path / "copy.c").write_text(
        "void copy(char *dst, char *src) { strcpy(dst, src); }\n",
        encoding="utf-8",
    )
    parsed = await SourceProjectParser().analyze(
        ProjectInput(task_id="task-mixed", target_id="target-mixed", project_path=str(tmp_path))
    )

    findings = await MultiLanguageSourceAuditor().audit(parsed)

    assert {item.producer for item in findings} == {"PythonSourceAuditor", "NativeSourceAuditor"}
