"""Dependency-free, non-executing implementation of the binary analyzer port."""

import asyncio
import hashlib
import logging
import re
import stat
from pathlib import Path
from typing import Any

from vulnagent.analyzers.binary.common import inspect_packing_signals
from vulnagent.contracts import (
    BinaryAnalysisRequest,
    BinaryAnalysisResult,
    ModuleExecutionError,
)

from ._elf import parse_elf
from ._callsite import inspect_pe_x64_callsites
from ._pe import parse_pe
from ._reader import ParseLimits, entropy

logger = logging.getLogger(__name__)


class StaticBinaryReverseAnalyzer:
    """Extract bounded PE/ELF facts without executing targets or invoking tools."""

    def __init__(self, limits: ParseLimits | None = None) -> None:
        self.limits = limits or ParseLimits()

    async def analyze(self, request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
        """Read a regular file and return the existing public result contract.

        Malformed, unsupported, unreadable and oversized inputs raise
        ModuleExecutionError. This coroutine offloads bounded static work to a
        thread; cancellation does not terminate an already-running worker.
        """
        return await asyncio.to_thread(self._analyze, request)

    def _analyze(self, request: BinaryAnalysisRequest) -> BinaryAnalysisResult:
        path = Path(request.path)
        try:
            if not stat.S_ISREG(path.stat().st_mode):
                raise ModuleExecutionError("Binary input must be a regular file")
            with path.open("rb") as stream:
                data = stream.read(self.limits.max_file_bytes + 1)
        except (OSError, ValueError) as exc:
            raise ModuleExecutionError(f"Cannot read binary input: {exc}") from exc
        if len(data) > self.limits.max_file_bytes:
            raise ModuleExecutionError("Binary input exceeds max_file_bytes")
        if data.startswith(b"MZ"):
            parsed = parse_pe(data, self.limits)
        elif data.startswith(b"\x7fELF"):
            parsed = parse_elf(data, self.limits)
        else:
            raise ModuleExecutionError(
                "Unsupported binary format; expected PE or ELF magic"
            )
        strings, string_locations, truncated = self._strings(data)
        if truncated:
            parsed.warnings.append("String output was truncated by ParseLimits")
        metadata: dict[str, Any] = {
            "analyzer": "static-binary-reverse",
            "metadata_version": 1,
            "mock": False,
            "executed": False,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
            "bits": parsed.bits,
            "byte_order": parsed.byte_order,
            "entry_point": parsed.entry_point,
            "entropy": entropy(data),
            "sections": parsed.sections,
            "exports": parsed.exports,
            "string_locations": string_locations,
            "strings_truncated": truncated,
            "warnings": parsed.warnings,
            "format_details": parsed.details,
            "callsite_semantics": inspect_pe_x64_callsites(data, parsed),
            "capabilities": {
                "headers": True,
                "sections": True,
                "imports_exports": "PE normal directories / ELF section-backed symbols",
                "function_discovery": "ELF declared symbols only",
                "callsite_semantics": (
                    "optional bounded PE x64 decoding; no CFG or reachability proof"
                ),
                "cfg": "not available from structural parsing; static result.cfg is empty",
                "decompilation": False,
                "unpacking": False,
                "external_adapters": "optional and explicitly authorized",
            },
        }
        logger.debug(
            "Static binary analysis completed for target %s (%s)",
            request.target_id,
            parsed.file_format,
        )
        result = BinaryAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            path=request.path,
            file_format=parsed.file_format,
            architecture=parsed.architecture,
            strings=strings,
            imports=parsed.imports,
            functions=parsed.functions,
            # Structural parsing does not decode instructions, so it must not infer CFG.
            metadata=metadata,
        )
        result.metadata["packing_signals"] = inspect_packing_signals(result)
        return result

    def _strings(self, data: bytes) -> tuple[list[str], list[dict[str, Any]], bool]:
        limits = self.limits
        records: list[dict[str, Any]] = []
        truncated = False
        patterns = (
            (rb"[\x20-\x7e]{%d,}" % limits.min_string_chars, "ascii", 1),
            (rb"(?:[\x20-\x7e]\x00){%d,}" % limits.min_string_chars, "utf-16-le", 2),
            (rb"(?:\x00[\x20-\x7e]){%d,}" % limits.min_string_chars, "utf-16-be", 2),
        )
        for pattern, encoding, width in patterns:
            for match in re.finditer(pattern, data):
                if len(records) >= limits.max_strings:
                    truncated = True
                    break
                raw_length = match.end() - match.start()
                byte_limit = limits.max_string_bytes // width * width
                if byte_limit < width:
                    truncated = True
                    continue
                clipped = raw_length > byte_limit
                value = data[
                    match.start() : min(match.end(), match.start() + byte_limit)
                ].decode(encoding)
                records.append(
                    {
                        "value": value,
                        "offset": match.start(),
                        "encoding": encoding,
                        "truncated": clipped,
                    }
                )
                truncated |= clipped
        records.sort(key=lambda item: (item["offset"], item["encoding"]))
        return (
            list(dict.fromkeys(item["value"] for item in records)),
            records,
            truncated,
        )
