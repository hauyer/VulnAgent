"""Call-target resolution and import-location tests (audit-consumable output)."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.analyzers.source.parser.python_resolver import (
    build_bindings,
    resolve_call_graph,
)
from vulnagent.contracts import ProjectInput


# ---------------------------------------------------------------------------
# Pure resolver behaviour
# ---------------------------------------------------------------------------

def resolve(raw: dict[str, set[str]], symbols: list[dict], modules: set[str],
            bindings: dict[str, dict[str, str]] | None = None) -> dict[str, list[str]]:
    return resolve_call_graph(raw, symbols, modules, bindings or {})


def test_resolves_local_and_self_calls_only() -> None:
    symbols = [
        {"qualified_name": "app.helper", "kind": "function"},
        {"qualified_name": "app.Service", "kind": "class"},
        {"qualified_name": "app.Service.run", "kind": "method"},
        {"qualified_name": "app.Service.finish", "kind": "method"},
    ]
    raw = {
        "app.Service.run": {"helper", "self.finish", "os.getcwd"},
        "app.helper": {"print"},
    }
    assert resolve(raw, symbols, {"app"}) == {
        "app.Service.run": ["app.Service.finish", "app.helper", "os.getcwd"],
        "app.helper": ["print"],
    }


def test_resolves_cross_module_imports_and_aliases() -> None:
    symbols = [
        {"qualified_name": "app.main", "kind": "function"},
        {"qualified_name": "pkg.tools.util", "kind": "function"},
        {"qualified_name": "pkg.tools.clean", "kind": "function"},
    ]
    bindings = {
        "app": {
            "util": "pkg.tools.util",
            "pt": "pkg.tools",
        }
    }
    raw = {"app.main": {"util", "pt.clean", "subprocess.run"}}
    assert resolve(raw, symbols, {"app", "pkg.tools"}, bindings) == {
        "app.main": ["pkg.tools.clean", "pkg.tools.util", "subprocess.run"],
    }


def test_full_dotted_module_path_that_is_defined_is_kept() -> None:
    symbols = [{"qualified_name": "pkg.tools.util", "kind": "function"}]
    raw = {"app.main": {"pkg.tools.util"}}
    assert resolve(raw, symbols, {"pkg.tools"}) == {
        "app.main": ["pkg.tools.util"]
    }


def test_build_bindings_handles_relative_imports() -> None:
    assert build_bindings("pkg.mod", [{"is_from": True, "level": 1,
                                       "module": "", "name": "sibling",
                                       "asname": None}]) == {
        "sibling": "pkg.sibling"
    }
    assert build_bindings("pkg.a.b", [{"is_from": True, "level": 2,
                                       "module": "common", "name": "c",
                                       "asname": None}]) == {
        "c": "pkg.common.c"
    }
    # relative import above the repo root cannot be resolved -> skipped
    assert build_bindings("main", [{"is_from": True, "level": 1,
                                    "module": "", "name": "x",
                                    "asname": None}]) == {}
    # plain ``import a.b`` binds nothing useful for resolution
    assert build_bindings("main", [{"is_from": False, "level": 0,
                                    "module": "a.b", "name": "a.b",
                                    "asname": None}]) == {}


async def analyze_project(tmp_path: Path) -> dict:
    result = await SourceProjectParser().analyze(
        ProjectInput(
            task_id="task-1",
            target_id="target-1",
            project_path=str(tmp_path),
        )
    )
    return {
        "call_graph": result.call_graph,
        "symbols": result.symbols,
        "imports": result.metadata["imports"],
        "files": result.files,
    }


@pytest.mark.asyncio
async def test_project_parser_resolves_cross_module_imports(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from package.helpers import utility as u\n"
        "\n"
        "def run():\n"
        "    return u() + os.getcwd()\n",
        encoding="utf-8",
    )
    package = tmp_path / "package"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text(
        "def utility():\n"
        "    return 1\n"
        "\n"
        "def cleanup():\n"
        "    return 2\n",
        encoding="utf-8",
    )

    parsed = await analyze_project(tmp_path)

    assert parsed["call_graph"] == {
        "app.run": ["os.getcwd", "package.helpers.utility"],
        "package.helpers.cleanup": [],
        "package.helpers.utility": [],
    }
    app_imports = parsed["imports"]["app.py"]
    assert {entry["name"] for entry in app_imports} == {"os", "utility"}
    alias = next(entry for entry in app_imports if entry["name"] == "utility")
    assert alias["asname"] == "u"
    assert alias["is_from"] is True
    assert alias["module"] == "package.helpers"
    assert alias["line"] == 2
    assert alias["column"] == 0
    plain = next(entry for entry in app_imports if entry["name"] == "os")
    assert plain["is_from"] is False
    assert plain["is_relative"] is False
    assert parsed["imports"]["package/helpers.py"] == []


@pytest.mark.asyncio
async def test_project_parser_resolves_relative_imports(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    (package / "__init__.py").parent.mkdir(exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "service.py").write_text(
        "from . import helpers\n"
        "\n"
        "def serve():\n"
        "    return helpers.work()\n",
        encoding="utf-8",
    )
    (package / "helpers.py").write_text(
        "def work():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    parsed = await analyze_project(tmp_path)

    assert parsed["call_graph"] == {
        "pkg.helpers.work": [],
        "pkg.service.serve": ["pkg.helpers.work"],
    }
    service_imports = parsed["imports"]["pkg/service.py"]
    assert service_imports[0]["is_relative"] is True
    assert service_imports[0]["level"] == 1
    assert service_imports[0]["name"] == "helpers"
