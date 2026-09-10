"""Architecture guard for the single FastAPI business backend."""

import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_typescript_business_backend_does_not_exist() -> None:
    forbidden = (
        ROOT / "server" / "orchestrator.ts",
        ROOT / "server" / "db.ts",
        ROOT / "server" / "routes.ts",
        ROOT / "server.ts",
    )
    assert not any(path.exists() for path in forbidden)


def test_frontend_scripts_use_vite_not_a_second_business_server() -> None:
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    scripts = package["scripts"]
    assert scripts["dev"] == "vite"
    assert scripts["build"] == "vite build"
    assert "express" not in package.get("dependencies", {})


def test_frontend_has_one_contract_mapping_and_no_python_internal_imports() -> None:
    assert (ROOT / "src" / "types.ts").is_file()
    assert not (ROOT / "frontend" / "src" / "types" / "index.ts").exists()
    for path in (ROOT / "src").rglob("*.ts*"):
        source = path.read_text(encoding="utf-8")
        module_specifiers = re.findall(
            r"(?:from\s+|import\s*\()\s*['\"]([^'\"]+)['\"]",
            source,
        )
        assert not any("vulnagent" in item or item.endswith(".py") for item in module_specifiers)


def test_frozen_runtime_defaults_are_documented_consistently() -> None:
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for setting in (
        "MAX_AGENT_STEPS=15",
        "MAX_ROUTE_REPEATS=2",
        "MAX_ANALYSIS_RETRIES=1",
    ):
        assert setting in env_example
        assert setting in readme
