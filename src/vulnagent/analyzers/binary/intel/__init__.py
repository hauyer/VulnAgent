"""V0.7 Binary Intelligence: semantic binary analysis (xref / chains / evidence)."""

from .catalog import DANGEROUS_APIS, INPUT_APIS, dangerous_category, input_source_kind
from .evidence import build_binary_evidence_graph
from .xref import BinaryXrefAnalyzer

__all__ = [
    "BinaryXrefAnalyzer",
    "build_binary_evidence_graph",
    "DANGEROUS_APIS",
    "INPUT_APIS",
    "dangerous_category",
    "input_source_kind",
]
