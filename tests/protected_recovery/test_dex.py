"""DEX/APK intake remains bounded and checksum-verifiable."""

import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

from vulnagent.analyzers.binary.reverse import StaticBinaryReverseAnalyzer, repair_dex_header
from vulnagent.contracts import BinaryAnalysisRequest


def make_dex() -> bytes:
    data = bytearray(112)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 32, len(data), 112, 0x12345678)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


async def test_static_analyzer_accepts_checksum_valid_dex(tmp_path: Path) -> None:
    path = tmp_path / "classes.dex"
    path.write_bytes(make_dex())
    result = await StaticBinaryReverseAnalyzer().analyze(
        BinaryAnalysisRequest(task_id="task", target_id="target", path=str(path))
    )
    assert result.file_format == "DEX"
    assert result.architecture == "dalvik"
    assert result.metadata["format_details"]["checksum_valid"] is True
    assert result.metadata["format_details"]["signature_valid"] is True


async def test_static_analyzer_inventories_apk_dex_entries(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", make_dex())
        archive.writestr("classes2.dex", make_dex())
    path = tmp_path / "owned.apk"
    path.write_bytes(buffer.getvalue())
    result = await StaticBinaryReverseAnalyzer().analyze(
        BinaryAnalysisRequest(task_id="task", target_id="target", path=str(path))
    )
    assert result.file_format == "APK"
    assert result.metadata["format_details"]["dex_entry_count"] == 2


async def test_memory_captured_dex_header_is_repaired_before_validation(tmp_path: Path) -> None:
    damaged = bytearray(make_dex())
    damaged[8:32] = b"\0" * 24
    repaired = repair_dex_header(bytes(damaged))
    path = tmp_path / "captured.dex"
    path.write_bytes(repaired)
    result = await StaticBinaryReverseAnalyzer().analyze(
        BinaryAnalysisRequest(task_id="task", target_id="target", path=str(path))
    )
    assert result.metadata["format_details"]["checksum_valid"] is True
    assert result.metadata["format_details"]["signature_valid"] is True
