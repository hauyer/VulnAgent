"""Function-level taint summaries (V0.6 interprocedural source analysis).

A ``FunctionSummary`` captures, for one function, how tainted parameters flow:

* ``param_to_sinks``   — ``param -> [(category, sink)]``: a tainted argument
  reaching this parameter can trigger the listed sink inside the body.
* ``param_taints_return`` — parameters whose taint propagates to the return
  value (so callers can track it onward).
* ``sanitized_params`` — ``param -> [categories]``: categories for which the
  body applies an explicit sanitizer before the sink.

The auditor computes these from the function body without executing it, then
uses them at call sites to resolve cross-function (A -> B -> C -> sink) taint
without re-analyzing callees.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """Neutral taint behavior of one function, keyed by parameter name."""

    name: str
    # positional parameter names (self/cls excluded), in declaration order
    parameters: tuple[str, ...] = ()
    # parameter -> [(category, sink)]
    param_to_sinks: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    # parameters whose taint reaches the return expression
    param_taints_return: frozenset[str] = frozenset()
    # parameter -> categories explicitly sanitized before the sink
    sanitized_params: dict[str, list[str]] = field(default_factory=dict)

    def sinks_for(self, parameter: str) -> list[tuple[str, str]]:
        return list(self.param_to_sinks.get(parameter, []))

    def taints_return(self, parameter: str) -> bool:
        return parameter in self.param_taints_return

    def categories_triggered_by(self, parameter: str) -> frozenset[str]:
        return frozenset(category for category, _ in self.param_to_sinks.get(parameter, []))


__all__ = ["FunctionSummary"]
