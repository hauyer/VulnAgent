"""V0.6 interprocedural taint tests: function summaries resolve A->B->C->sink."""

from pathlib import Path

from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import ProjectInput


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


VULNERABLE_CHAIN = (
    "import subprocess\n"
    "\n"
    "def execute_shell(command: str):\n"
    "    return subprocess.run(command, shell=True, check=False)\n"
    "\n"
    "def run_build(command: str):\n"
    "    return execute_shell(command)\n"
    "\n"
    "def deploy(version: str):\n"
    "    command = 'deploy --version ' + version\n"
    "    return run_build(command)\n"
    "\n"
    "def main():\n"
    "    version = input('version: ')\n"
    "    deploy(version)\n"
)

SANITIZED_CHAIN = (
    "import shlex\n"
    "import subprocess\n"
    "\n"
    "def execute_shell(command: str):\n"
    "    safe = shlex.quote(command)\n"
    "    return subprocess.run(safe, shell=True, check=False)\n"
    "\n"
    "def run_build(command: str):\n"
    "    return execute_shell(command)\n"
    "\n"
    "def deploy(version: str):\n"
    "    command = 'deploy --version ' + version\n"
    "    return run_build(command)\n"
    "\n"
    "def main():\n"
    "    version = input('version: ')\n"
    "    deploy(version)\n"
)


async def test_three_layer_helper_chain_detected(tmp_path: Path) -> None:
    findings = await _audit(tmp_path, VULNERABLE_CHAIN)

    command_findings = [item for item in findings if item.cwe_id == "CWE-78"]
    assert command_findings, "interprocedural chain must be detected"
    sinks = {item.metadata["sink"] for item in command_findings}
    assert any("execute_shell->subprocess.run" in sink for sink in sinks)
    assert any("run_build->execute_shell->subprocess.run" in sink for sink in sinks)
    assert any("deploy->run_build->execute_shell->subprocess.run" in sink for sink in sinks)

    chained = [item for item in command_findings if "->" in item.metadata["sink"]]
    assert chained, "interprocedural call-site matches must carry the chain"
    for item in chained:
        assert "interprocedural taint via project-wide function summaries" in item.metadata["limitations"]
        assert item.metadata["source_kinds"] == ["input"]


async def test_sanitized_chain_has_no_false_positive(tmp_path: Path) -> None:
    findings = await _audit(tmp_path, SANITIZED_CHAIN)
    assert findings == [], "sanitized chain must produce zero findings"


async def test_direct_helper_sink_detected_at_callsite(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n"
        "\n"
        "def run_command(command: str):\n"
        "    os.system(command)\n"
        "\n"
        "def main():\n"
        "    payload = input()\n"
        "    run_command(payload)\n",
    )

    # The callee's parameter-driven dynamic candidate is modeled by the
    # summary; only the call-site (interprocedural) match is reported.
    assert len(findings) == 1
    assert any("run_command->os.system" in item.metadata["sink"] for item in findings)


async def test_return_taint_propagates_through_summary(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n"
        "\n"
        "def identity(value):\n"
        "    return value\n"
        "\n"
        "def main():\n"
        "    payload = input()\n"
        "    resolved = identity(payload)\n"
        "    os.system(resolved)\n",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["sink"] == "os.system"
    assert finding.metadata["source_kinds"] == ["input"]
    assert any("identity->value->return" in marker for marker in finding.metadata["taint_path"])


async def test_summary_ignores_unrelated_parameter(tmp_path: Path) -> None:
    # A callee whose summary only propagates ``y`` must not taint the result
    # when the tainted argument is bound to the ignored parameter ``x``.
    findings = await _audit(
        tmp_path,
        "import os\n"
        "\n"
        "def wrap(x, y):\n"
        "    return y\n"
        "\n"
        "def main():\n"
        "    payload = input()\n"
        "    resolved = wrap(payload, 'fixed')\n"
        "    os.system(resolved)\n",
    )

    assert len(findings) == 0, "taint through an ignored parameter must not propagate"


async def test_function_without_effect_keeps_conservative_passthrough(
    tmp_path: Path,
) -> None:
    # A helper with no sink/return behavior has no summary, so the call keeps
    # the legacy conservative passthrough (taint survives, marked by the call).
    findings = await _audit(
        tmp_path,
        "import os\n"
        "\n"
        "def unrelated(value):\n"
        "    return 'fixed'\n"
        "\n"
        "def main():\n"
        "    payload = input()\n"
        "    resolved = unrelated(payload)\n"
        "    os.system(resolved)\n",
    )

    assert len(findings) == 1
    assert findings[0].metadata["sink"] == "os.system"
    assert findings[0].metadata["source_kinds"] == ["input"]


async def test_cross_file_helper_chain_detected(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text(
        "import subprocess\n"
        "def run_build(command: str):\n"
        "    return subprocess.run(command, shell=True, check=False)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from helper import run_build\n"
        "def main():\n"
        "    version = input('version: ')\n"
        "    run_build(version)\n",
        encoding="utf-8",
    )
    parsed = await SourceProjectParser().analyze(
        ProjectInput(task_id="task-1", target_id="target-1", project_path=str(tmp_path))
    )
    findings = await PythonSourceAuditor().audit(parsed)

    chained = [item for item in findings if "->" in item.metadata["sink"]]
    assert chained, "cross-file call site must resolve the helper summary"
    assert any("run_build->subprocess.run" in item.metadata["sink"] for item in chained)
    assert all(item.metadata["source_kinds"] == ["input"] for item in chained)


async def test_validate_guard_returns_clean_path(tmp_path: Path) -> None:
    # ``if not validate(x): return`` is a terminating guard: statements after
    # the If only run when validation passed -> zero findings.
    findings = await _audit(
        tmp_path,
        "import os\n"
        "def validate(value: str) -> bool:\n"
        "    return len(value) < 64\n"
        "def main():\n"
        "    payload = input()\n"
        "    if not validate(payload):\n"
        "        return\n"
        "    os.system(payload)\n",
    )
    assert findings == [], "validated path must not be reported"


async def test_guard_false_comparison_shape(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n"
        "def validate(value: str) -> bool:\n"
        "    return value.isalnum()\n"
        "def main():\n"
        "    payload = input()\n"
        "    if validate(payload) is False:\n"
        "        raise ValueError('bad input')\n"
        "    os.system(payload)\n",
    )
    assert findings == [], "raise guard is a validation barrier too"


async def test_guard_covers_helper_call(tmp_path: Path) -> None:
    findings = await _audit(
        tmp_path,
        "import os\n"
        "def run_command(command: str):\n"
        "    os.system(command)\n"
        "def validate(value: str) -> bool:\n"
        "    return value.isalnum()\n"
        "def main():\n"
        "    payload = input()\n"
        "    if not validate(payload):\n"
        "        return\n"
        "    run_command(payload)\n",
    )
    assert findings == [], "guard must silence callee-sink matches on the validated path"


async def test_non_terminating_guard_is_not_a_barrier(tmp_path: Path) -> None:
    # Body does not return/raise -> execution may continue with tainted data.
    findings = await _audit(
        tmp_path,
        "import os\n"
        "def validate(value: str) -> bool:\n"
        "    return value.isalnum()\n"
        "def main():\n"
        "    payload = input()\n"
        "    if not validate(payload):\n"
        "        print('invalid input')\n"
        "    os.system(payload)\n",
    )
    assert len(findings) == 1, "non-terminating branch must keep the candidate"
