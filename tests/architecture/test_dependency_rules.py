"""Prevent cross-owner dependencies from silently reappearing."""

import ast
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[2] / "src" / "vulnagent"

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


def test_agents_do_not_depend_on_provider_sdks() -> None:
    forbidden = ("openai", "zhipuai", "langchain_deepseek", "langchain_openai", "kimi")
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
        text = path.read_text(encoding="utf-8")
        if "VulnerabilityStatus.CONFIRMED" in text or "VulnerabilityStatus.REJECTED" in text:
            violations.append(str(path.relative_to(SOURCE_ROOT)))
    assert violations == []


def test_public_contract_names_are_not_redefined() -> None:
    protected = {"Task", "AgentMessage", "AnalysisContext", "VulnerabilityCandidate", "Evidence", "VerificationResult"}
    violations: list[str] = []
    for path in SOURCE_ROOT.rglob("*.py"):
        if SOURCE_ROOT / "contracts" in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in protected:
                violations.append(f"{path.relative_to(SOURCE_ROOT)}:{node.name}")
    assert violations == []


def test_fuzz_boundary_has_no_uncontrolled_process_execution() -> None:
    forbidden_text = ("shell=True", "subprocess.run", "subprocess.Popen", "os.system")
    violations: list[str] = []
    for path in (SOURCE_ROOT / "fuzz").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(item in text for item in forbidden_text):
            violations.append(str(path.relative_to(SOURCE_ROOT)))
    assert violations == []
