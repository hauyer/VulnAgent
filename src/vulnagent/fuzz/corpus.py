"""V0.8 Dynamic Confirmation: seed and corpus management.

``SeedGenerator`` derives initial inputs from a candidate's sink/source
shape; ``CorpusManager`` deduplicates and persists fuzz inputs by content
hash.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

from vulnagent.contracts import VulnerabilityCandidate

_SEED_TEMPLATES: dict[str, list[str]] = {
    "div": ["0", "1", "-1", "999999", "0000", " ", "0\n", "1\n"],
    "subscript": ["0", "1", "-1", "2", "99", "999999999", "1\n", "-1\n"],
    "subscript-": ["0", "1", "-1", "2", "99", "999999999", "1\n", "-1\n"],
}


class SeedGenerator:
    """Generate an initial corpus from a candidate's sink type."""

    def generate(self, candidate: VulnerabilityCandidate) -> list[bytes]:
        sink = str(candidate.metadata.get("sink", ""))
        templates = _SEED_TEMPLATES.get(sink, ["0", "1", "-1", "999999", "abc"])
        seeds: list[bytes] = []
        for template in templates:
            value = template.encode()
            if value not in seeds:
                seeds.append(value)
        return seeds


class CorpusManager:
    """Deduplicated, persistent input corpus."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root
        self._inputs: dict[str, bytes] = {}

    def add(self, input_bytes: bytes) -> bool:
        digest = sha256(input_bytes).hexdigest()
        if digest in self._inputs:
            return False
        self._inputs[digest] = input_bytes
        return True

    def add_many(self, inputs: list[bytes]) -> int:
        added = 0
        for input_bytes in inputs:
            if self.add(input_bytes):
                added += 1
        return added

    @property
    def inputs(self) -> list[bytes]:
        return list(self._inputs.values())

    @property
    def size(self) -> int:
        return len(self._inputs)

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        for digest, payload in self._inputs.items():
            (directory / f"seed-{digest[:16]}").write_bytes(payload)
        return directory

    def load(self, directory: Path) -> int:
        if not directory.is_dir():
            return 0
        count = 0
        for path in sorted(directory.iterdir()):
            if path.is_file():
                self.add(path.read_bytes())
                count += 1
        return count
