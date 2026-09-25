"""V0.8 Dynamic Confirmation: fuzz harness, corpus, coverage, triage, backends."""

from .backend import FuzzBackend, FuzzOutcome, PythonFuzzBackend
from .corpus import CorpusManager, SeedGenerator
from .harness import CoverageTracker, HarnessGenerator
from .libfuzzer import (
    LibFuzzerRunStats,
    RealLibFuzzerEngine,
    parse_libfuzzer_output,
)
from .triage import CrashRecord, CrashTriage

__all__ = [
    "FuzzBackend",
    "FuzzOutcome",
    "PythonFuzzBackend",
    "CorpusManager",
    "SeedGenerator",
    "CoverageTracker",
    "HarnessGenerator",
    "CrashRecord",
    "CrashTriage",
    "LibFuzzerRunStats",
    "RealLibFuzzerEngine",
    "parse_libfuzzer_output",
]
