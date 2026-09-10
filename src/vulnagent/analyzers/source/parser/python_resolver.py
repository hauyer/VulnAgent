"""Best-effort resolution of Python call targets to project-internal symbols.

``SourceAnalysisResult.call_graph`` records, per caller (a module-qualified
callable name), the set of syntactic call targets collected from its body.
Those targets are usually *not* module-qualified yet (``helper``,
``self.finish``, ``ph.util`` ...).  This module resolves them, when possible,
to the qualified name of a symbol *defined inside the parsed project*
(``main.helper``, ``main.Service.finish``, ``pkg.tools.ph_util`` ...).

Rules (conservative: a target is rewritten only when a concrete definition
is found, otherwise the original syntactic name is kept):

1. ``self.<name>`` / ``cls.<name>`` inside a method resolve against the
   enclosing class when that method exists in the symbol index;
2. a bare name resolves to a module-level definition of the caller's module
   or to an imported symbol (``from x import y``) defined in the project;
3. a dotted target whose head is an import alias (``import a.b as ab``,
   ``from x import y`` where ``y`` is a submodule) resolves by replacing the
   alias with its module path;
4. everything else (stdlib/third-party calls, calls through variables,
   dynamic dispatch) is left unchanged.

Because resolution is heuristic, it never *invents* edges: a rewritten edge
always points to a symbol that actually exists in the parsed project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "ModuleIndex",
    "build_bindings",
    "build_module_index",
    "resolve_call_graph",
    "resolve_call_graph_for_files",
    "resolve_token",
]


@dataclass(frozen=True, slots=True)
class ModuleIndex:
    """Index over the symbols and modules of one parsed project."""

    modules: frozenset[str]
    def_index: frozenset[str]
    class_names: frozenset[str]
    module_local: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    @property
    def caller_modules(self) -> frozenset[str]:
        """Return the module names that can own callers."""
        return self.modules


def build_module_index(
    symbols: list[dict[str, Any]],
    module_names: set[str] | frozenset[str] | list[str],
) -> ModuleIndex:
    """Index parsed symbols so call targets can be resolved cheaply."""
    modules = frozenset(module_names)
    def_index: set[str] = set()
    class_names: set[str] = set()
    module_local: dict[str, dict[str, str]] = {}

    for symbol in symbols:
        qualified = str(symbol.get("qualified_name", ""))
        if not qualified:
            continue
        def_index.add(qualified)
        kind = str(symbol.get("kind", ""))
        if kind == "class":
            class_names.add(qualified)

        module = _module_prefix(qualified, modules)
        if module is None:
            continue
        remainder = qualified[len(module) + 1 :]
        if not remainder or "." in remainder:
            continue  # only module-level definitions are addressable by name
        module_local.setdefault(module, {})[remainder] = qualified

    return ModuleIndex(
        modules=modules,
        def_index=frozenset(def_index),
        class_names=frozenset(class_names),
        module_local={
            module: dict(names)
            for module, names in sorted(module_local.items())
        },
    )


def build_bindings(
    module: str,
    import_entries: list[Mapping[str, Any]],
) -> dict[str, str]:
    """Map names bound in ``module`` to fully qualified module/symbol paths.

    Only import forms that can be resolved statically are mapped:

    - ``import a.b as ab``  ->  ``ab`` : ``a.b``
    - ``from x import y``   ->  ``y``  : ``x.y`` (absolute) or the
      package-relative equivalent
    - ``from x import y as z`` -> ``z`` : ``x.y``

    Plain ``import a.b`` binds the *root* name at runtime but is useless for
    resolution (call targets already spell the full dotted path), so it is
    intentionally not mapped.  Relative-import bases are approximated from
    the importing module name; unresolvable cases are skipped.
    """
    bindings: dict[str, str] = {}
    for entry in import_entries:
        name = str(entry.get("name") or "")
        asname = entry.get("asname")
        is_from = bool(entry.get("is_from"))
        level = int(entry.get("level") or 0)
        raw_module = str(entry.get("module") or "")

        if not is_from:
            if asname:
                bindings[str(asname)] = raw_module
            continue

        # ``from ... import name`` -> target module path
        target_module: str | None
        if level <= 0:
            target_module = raw_module or None
        else:
            base = _relative_base(module, level)
            if base is None:
                continue
            target_module = f"{base}.{raw_module}" if raw_module else base

        if not target_module:
            continue
        if name == "*":
            continue
        bindings[str(asname or name)] = f"{target_module}.{name}"
    return bindings


def resolve_call_graph(
    call_graph: Mapping[str, set[str]] | Mapping[str, list[str]],
    symbols: list[dict[str, Any]],
    module_names: set[str] | frozenset[str],
    bindings_by_module: Mapping[str, Mapping[str, str]],
) -> dict[str, list[str]]:
    """Return a new call graph whose call targets are best-effort resolved."""
    index = build_module_index(symbols, module_names)
    resolved: dict[str, list[str]] = {}
    for caller, raw_targets in sorted(call_graph.items()):
        caller_module = _module_prefix(str(caller), index.modules)
        bindings = (
            bindings_by_module.get(caller_module, {})
            if caller_module is not None
            else {}
        )
        resolved[caller] = sorted(
            {
                resolve_token(
                    str(target),
                    caller_qname=str(caller),
                    index=index,
                    bindings=bindings,
                )
                for target in raw_targets
            }
        )
    return resolved


def resolve_call_graph_for_files(
    call_graph: Mapping[str, set[str]] | Mapping[str, list[str]],
    symbols: list[dict[str, Any]],
    parsed_files: Iterable[Any],
) -> dict[str, list[str]]:
    """Resolve a raw call graph given the per-file parse results.

    ``parsed_files`` items only need ``module`` and ``imports`` attributes
    (see ``PythonFileParse``), so this helper can be shared by every parser
    without depending on the concrete per-file result type.
    """
    module_names: set[str] = set()
    bindings_by_module: dict[str, dict[str, str]] = {}
    for parsed_file in parsed_files:
        module = getattr(parsed_file, "module", None)
        if not module:
            continue
        module_names.add(module)
        bindings_by_module[module] = build_bindings(
            module, getattr(parsed_file, "imports", [])
        )
    return resolve_call_graph(
        call_graph,
        symbols=symbols,
        module_names=module_names,
        bindings_by_module=bindings_by_module,
    )


def resolve_token(
    token: str,
    *,
    caller_qname: str,
    index: ModuleIndex,
    bindings: Mapping[str, str],
) -> str:
    """Resolve one syntactic call target or return it unchanged."""
    if token in index.def_index:
        return token

    parts = token.split(".")
    head = parts[0]
    rest = parts[1:]

    # self.<name> / cls.<name>
    if head in {"self", "cls"} and rest:
        enclosing = _enclosing_class(caller_qname, index.class_names)
        if enclosing is not None:
            candidate = f"{enclosing}.{'.'.join(rest)}"
            if candidate in index.def_index:
                return candidate
        return token

    if len(parts) == 1:
        # bare module-local definition
        caller_module = _module_prefix(caller_qname, index.modules)
        if caller_module is not None:
            local = index.module_local.get(caller_module, {}).get(head)
            if local is not None:
                return local
        # bare imported symbol defined in the project
        imported = bindings.get(head)
        if imported is not None and imported in index.def_index:
            return imported
        return token

    # dotted target whose head is an import alias
    alias_target = bindings.get(head)
    if alias_target is not None:
        candidate = (
            f"{alias_target}.{'.'.join(rest)}" if rest else alias_target
        )
        if candidate in index.def_index:
            return candidate

    return token


def _module_prefix(
    qualified: str,
    modules: frozenset[str],
) -> str | None:
    """Longest dotted prefix of ``qualified`` that is a parsed module."""
    parts = qualified.split(".")
    for end in range(len(parts), 0, -1):
        prefix = ".".join(parts[:end])
        if prefix in modules:
            return prefix
    return None


def _enclosing_class(
    caller_qname: str,
    class_names: frozenset[str],
) -> str | None:
    """Return the class scope of a method caller, if it is a real class."""
    parts = caller_qname.split(".")
    for end in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:end])
        if prefix in class_names:
            return prefix
    return None


def _relative_base(module: str, level: int) -> str | None:
    """Approximate the package a relative import starts from.

    ``level == 1`` means the module's own package, ``level == 2`` its parent
    package, and so on.  When the level points above the repository root the
    import cannot be resolved and ``None`` is returned.
    """
    if level < 1:
        return None
    parts = module.split(".")
    if len(parts) <= level:
        return None
    return ".".join(parts[:-level])
