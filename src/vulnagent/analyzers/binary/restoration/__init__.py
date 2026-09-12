"""Program-restoration capability boundary."""

from .dynamic import FridaDexSnapshotProvider, RecordedSnapshotProvider, WindowsDebugSnapshotProvider
from .engine import ProgramRestorationEngine
from .imports import ImportTableRebuilder, RebuiltImportTable
from .models import ApiResolution, MemoryRegion, MemorySnapshot
from .pe_rebuild import PEImageRebuilder, RebuiltImage

__all__ = [
    "ApiResolution",
    "FridaDexSnapshotProvider",
    "MemoryRegion",
    "MemorySnapshot",
    "PEImageRebuilder",
    "ProgramRestorationEngine",
    "ImportTableRebuilder",
    "RebuiltImportTable",
    "RebuiltImage",
    "RecordedSnapshotProvider",
    "WindowsDebugSnapshotProvider",
]
