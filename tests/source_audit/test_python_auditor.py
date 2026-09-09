"""Tests for the explainable member-3 Python source auditor."""

from pathlib import Path

from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import (
    ProjectInput,
    SourceAnalysisResult,
    VulnerabilityStatus,
)


async def _audit(
    tmp_path: Path,
    source: str,
    *,
    filename: str = "app.py",
):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    parsed = await SourceProjectParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )
    return await PythonSourceAuditor().audit(parsed)


async def test_command_injection_resolves_import_alias_and_taint_path(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "import os as operating\n\n"
        "def run():\n"
        "    command = input()\n"
        "    operating.system(command)\n",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == "CWE-78"
    assert finding.status is VulnerabilityStatus.CANDIDATE
    assert finding.location is not None
    assert finding.location.file_path == "app.py"
    assert finding.location.function_name == "app.run"
    assert finding.location.line_start == 5
    assert finding.metadata["sink"] == "os.system"
    assert finding.metadata["rule_id"] == "VA-PY-CMD-001"
    assert finding.metadata["source_kinds"] == ["input"]
    assert finding.metadata["taint_path"]


async def test_route_parameter_is_treated_as_untrusted_input(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n\n"
        "@app.post('/run')\n"
        "def run(command: str):\n"
        "    os.system(command)\n",
    )

    assert [item.cwe_id for item in findings] == ["CWE-78"]
    assert findings[0].metadata["source_kinds"] == ["route_parameter:command"]


async def test_sql_injection_detects_formatted_tainted_query(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "def lookup(cursor):\n"
        "    user_id = input()\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n",
    )

    assert [item.cwe_id for item in findings] == ["CWE-89"]
    assert findings[0].metadata["category"] == "sql"


async def test_path_traversal_detects_tainted_file_name(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "def download():\n"
        "    name = input()\n"
        "    return open('/srv/files/' + name).read()\n",
    )

    assert [item.cwe_id for item in findings] == ["CWE-22"]
    assert findings[0].severity == "MEDIUM"


async def test_unsafe_deserialization_detects_tainted_pickle_input(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "import pickle\n\n"
        "def restore():\n"
        "    payload = input().encode()\n"
        "    return pickle.loads(payload)\n",
    )

    assert [item.cwe_id for item in findings] == ["CWE-502"]
    assert findings[0].metadata["sink"] == "pickle.loads"


async def test_dynamic_code_execution_detects_nonliteral_and_tainted_values(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "def first():\n"
        "    eval(input())\n\n"
        "def second(expression):\n"
        "    exec(expression)\n",
    )

    assert [item.cwe_id for item in findings] == ["CWE-95", "CWE-95"]
    assert findings[0].confidence > findings[1].confidence
    assert findings[1].metadata["source_kinds"] == ["dynamic_value"]


async def test_simple_branch_merge_preserves_taint(
    tmp_path: Path,
) -> None:
    findings = await _audit(
        tmp_path,
        "def run(flag):\n"
        "    value = input()\n"
        "    if flag:\n"
        "        expression = value\n"
        "    else:\n"
        "        expression = '1 + 1'\n"
        "    eval(expression)\n",
    )

    assert len(findings) == 1
    assert findings[0].metadata["source_kinds"] == ["input"]


async def test_safe_patterns_do_not_create_candidates(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n"
        "import subprocess\n"
        "import yaml\n"
        "from werkzeug.utils import secure_filename\n\n"
        "def safe(cursor):\n"
        "    value = input()\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ?', (value,))\n"
        "    yaml.safe_load(value)\n"
        "    subprocess.run(['echo', value])\n"
        "    name = secure_filename(value)\n"
        "    open(os.path.join('/srv/files', name)).read()\n"
        "    eval('1 + 1')\n",
    )

    assert findings == []


async def test_yaml_safe_loader_keyword_is_not_reported(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import yaml\n\n"
        "def load_document():\n"
        "    return yaml.load(input(), Loader=yaml.SafeLoader)\n",
    )

    assert findings == []


async def test_results_are_deduplicated_and_stably_sorted(tmp_path: Path) -> None:
    (tmp_path / "z.py").write_text(
        "import os\nos.system(input())\n", encoding="utf-8"
    )
    (tmp_path / "a.py").write_text(
        "import pickle\npickle.loads(input())\n", encoding="utf-8"
    )
    parsed = await SourceProjectParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )
    # Repeated inventory entries must not duplicate findings.
    parsed.files.append("z.py")

    findings = await PythonSourceAuditor().audit(parsed)

    assert [(item.location.file_path, item.cwe_id) for item in findings if item.location] == [
        ("a.py", "CWE-502"),
        ("z.py", "CWE-78"),
    ]


async def test_invalid_inventory_entries_and_broken_python_are_skipped(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("eval(input())\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("eval(input())\n", encoding="utf-8")
    result = SourceAnalysisResult(
        task_id="task-1",
        target_id="target-1",
        project_path=str(tmp_path),
        languages=["python"],
        files=["../outside.py", "broken.py", "missing.py", "notes.txt"],
    )

    assert await PythonSourceAuditor().audit(result) == []


async def test_missing_project_and_unsupported_language_return_empty(
    tmp_path: Path,
) -> None:
    missing = SourceAnalysisResult(
        task_id="task-1",
        target_id="target-1",
        project_path=str(tmp_path / "missing"),
        files=["app.py"],
    )
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    unsupported = SourceAnalysisResult(
        task_id="task-1",
        target_id="target-1",
        project_path=str(tmp_path),
        languages=["c"],
        files=["main.c"],
    )

    auditor = PythonSourceAuditor()
    assert await auditor.audit(missing) == []
    assert await auditor.audit(unsupported) == []
