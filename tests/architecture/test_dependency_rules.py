"""Prevent cross-owner dependencies from silently reappearing."""

import ast
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[2] / "src" / "vulnagent"

PRIVATE_TRACE_FIELDS = {
    "chain_of_thought",
    "private_reasoning",
    "hidden_reasoning",
    "raw_cot",
    "reasoning_tokens",
}

FORBIDDEN_PREFIXES = {
    "analyzers": ("vulnagent.agents", "vulnagent.core", "vulnagent.evidence", "vulnagent.fuzz", "vulnagent.report", "vulnagent.verification"),
    "fuzz": ("vulnagent.agents", "vulnagent.analyzers", "vulnagent.core", "vulnagent.report", "vulnagent.verification"),
    "verification": ("vulnagent.agents", "vulnagent.analyzers", "vulnagent.core", "vulnagent.fuzz", "vulnagent.report"),
    "evidence": ("vulnagent.agents", "vulnagent.analyzers", "vulnagent.core", "vulnagent.fuzz", "vulnagent.report", "vulnagent.verification"),
    "report": ("vulnagent.agents", "vulnagent.analyzers", "vulnagent.core", "vulnagent.fuzz", "vulnagent.verification"),
}


def imported_modules(path: Path) -> list[str]:
    """Extract absolute imports without executing project code."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def class_annotated_fields(path: Path, class_name: str) -> set[str]:
    """Return directly annotated fields for one class without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                item.target.id
                for item in node.body
                if isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
            }
    raise AssertionError(f"Class not found: {class_name}")


def test_capability_modules_do_not_cross_owner_boundaries() -> None:
    violations: list[str] = []
    for owner, forbidden in FORBIDDEN_PREFIXES.items():
        for path in (SOURCE_ROOT / owner).rglob("*.py"):
            for module in imported_modules(path):
                if module.startswith(forbidden):
                    violations.append(f"{path.relative_to(SOURCE_ROOT)} -> {module}")
    assert violations == []


def test_contracts_have_no_business_dependencies() -> None:
    violations: list[str] = []
    for path in (SOURCE_ROOT / "contracts").rglob("*.py"):
        for module in imported_modules(path):
            if module.startswith("vulnagent"):
                violations.append(f"{path.name} -> {module}")
    assert violations == []


def test_agents_do_not_import_concrete_capabilities() -> None:
    forbidden = ("vulnagent.analyzers", "vulnagent.fuzz", "vulnagent.verification", "vulnagent.evidence", "vulnagent.report")
    violations: list[str] = []
    for path in (SOURCE_ROOT / "agents").rglob("*.py"):
        for module in imported_modules(path):
            if module.startswith(forbidden):
                violations.append(f"{path.name} -> {module}")
    assert violations == []


def test_agent_runtime_does_not_import_concrete_capabilities() -> None:
    forbidden = ("vulnagent.analyzers", "vulnagent.fuzz", "vulnagent.verification", "vulnagent.evidence", "vulnagent.report")
    violations: list[str] = []
    for path in (SOURCE_ROOT / "agent_runtime").rglob("*.py"):
        for module in imported_modules(path):
            if module.startswith(forbidden):
                violations.append(f"{path.name} -> {module}")
    assert violations == []


def test_core_does_not_import_concrete_capabilities() -> None:
    forbidden = (
        "vulnagent.analyzers",
        "vulnagent.fuzz",
        "vulnagent.verification",
        "vulnagent.evidence",
        "vulnagent.report",
    )
    violations: list[str] = []
    for path in (SOURCE_ROOT / "core").rglob("*.py"):
        for module in imported_modules(path):
            if module.startswith(forbidden):
                violations.append(f"{path.name} -> {module}")
    assert violations == []


def test_agents_do_not_depend_on_provider_sdks() -> None:
    forbidden = (
        "openai",
        "anthropic",
        "deepseek",
        "zhipu",
        "zhipuai",
        "kimi",
        "langchain_anthropic",
        "langchain_deepseek",
        "langchain_openai",
    )
    violations: list[str] = []
    for owner in ("agents", "agent_runtime"):
        for path in (SOURCE_ROOT / owner).rglob("*.py"):
            for module in imported_modules(path):
                if module.startswith(forbidden):
                    violations.append(f"{path.relative_to(SOURCE_ROOT)} -> {module}")
    assert violations == []


def test_production_code_uses_contracts_not_compatibility_models() -> None:
    violations = []
    for path in SOURCE_ROOT.rglob("*.py"):
        if path == SOURCE_ROOT / "core" / "models.py":
            continue
        if "vulnagent.core.models" in imported_modules(path):
            violations.append(str(path.relative_to(SOURCE_ROOT)))
    assert violations == []


def test_only_verification_boundary_writes_final_finding_status() -> None:
    """CONFIRMED/REJECTED decisions must not leak into discovery modules."""
    violations: list[str] = []
    allowed = {SOURCE_ROOT / "verification", SOURCE_ROOT / "agents" / "verification_agent.py", SOURCE_ROOT / "contracts"}
    for path in SOURCE_ROOT.rglob("*.py"):
        if any(path == root or root in path.parents for root in allowed):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "VulnerabilityStatus"
                and node.attr in {"CONFIRMED", "REJECTED", "UNCERTAIN"}
            ):
                violations.append(str(path.relative_to(SOURCE_ROOT)))
                break
    assert violations == []


def test_public_contract_names_are_not_redefined() -> None:
    protected = {
        "Task",
        "AgentMessage",
        "AnalysisContext",
        "AgentResult",
        "DomainEvent",
        "Evidence",
        "VulnerabilityCandidate",
        "VerificationResult",
        "SourceAnalysisResult",
        "BinaryAnalysisResult",
        "FuzzResult",
        "ReportResult",
    }
    violations: list[str] = []
    for path in SOURCE_ROOT.rglob("*.py"):
        if SOURCE_ROOT / "contracts" in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in protected:
                violations.append(f"{path.relative_to(SOURCE_ROOT)}:{node.name}")
    assert violations == []


def test_runtime_state_does_not_duplicate_business_results() -> None:
    forbidden = {
        "finding",
        "findings",
        "evidence",
        "verification",
        "verifications",
        "report",
        "reports",
        "vulnerabilities",
        "analysis_context",
    }
    fields = class_annotated_fields(
        SOURCE_ROOT / "agent_runtime" / "state.py",
        "RuntimeState",
    )
    assert fields.isdisjoint(forbidden)


def test_public_trace_models_do_not_define_private_reasoning_fields() -> None:
    agent_fields = class_annotated_fields(
        SOURCE_ROOT / "contracts" / "agent.py",
        "AgentMessage",
    )
    event_fields = class_annotated_fields(
        SOURCE_ROOT / "contracts" / "events.py",
        "DomainEvent",
    )
    assert agent_fields.isdisjoint(PRIVATE_TRACE_FIELDS)
    assert event_fields.isdisjoint(PRIVATE_TRACE_FIELDS)


def test_concrete_mock_assembly_stays_out_of_core_and_runtime() -> None:
    guarded = [
        SOURCE_ROOT / "core" / "orchestrator.py",
        SOURCE_ROOT / "core" / "pipeline.py",
        SOURCE_ROOT / "agent_runtime" / "runtime.py",
    ]
    violations: list[str] = []
    for path in guarded:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id.startswith("Mock")
            ):
                violations.append(f"{path.name}:{node.func.id}")
    assert violations == []


def test_pipeline_has_no_fixed_full_workflow_stage_table() -> None:
    path = SOURCE_ROOT / "core" / "pipeline.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_names = {"stages", "pipeline_stages", "workflow_stages"}
    assigned_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assigned_names.add(target.id.casefold())
                elif isinstance(target, ast.Attribute):
                    assigned_names.add(target.attr.casefold())
    assert assigned_names.isdisjoint(forbidden_names)


def test_reviewer_does_not_assign_finding_status() -> None:
    path = SOURCE_ROOT / "agents" / "reviewer_agent.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
        if isinstance(target, ast.Attribute) and target.attr == "status"
    ]
    assert violations == []


def test_fuzz_boundary_has_no_uncontrolled_process_execution() -> None:
    forbidden_text = ("shell=True", "subprocess.run", "subprocess.Popen", "os.system")
    violations: list[str] = []
    for path in (SOURCE_ROOT / "fuzz").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(item in text for item in forbidden_text):
            violations.append(str(path.relative_to(SOURCE_ROOT)))
    assert violations == []
