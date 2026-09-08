"""PE/ELF structural reverse-analysis boundary."""

from ._reader import ParseLimits
from .adapters import Radare2Adapter, ToolRunResult, UpxAdapter, parse_radare2_json
from .artifacts import BinaryArtifactStore
from .mock import MockBinaryReverseAnalyzer
from .static import StaticBinaryReverseAnalyzer

__all__ = [
    "BinaryArtifactStore",
    "MockBinaryReverseAnalyzer",
    "ParseLimits",
    "Radare2Adapter",
    "StaticBinaryReverseAnalyzer",
    "ToolRunResult",
    "UpxAdapter",
    "parse_radare2_json",
]
