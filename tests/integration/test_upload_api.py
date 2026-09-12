"""Browser upload boundary tests: type checks, size bounds and safe paths."""

from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.api.routes import uploads


def _use_temp_upload_root(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(uploads, "UPLOAD_ROOT", tmp_path / "artifacts" / "uploads")
    monkeypatch.setattr(uploads, "REPOSITORY_ROOT", tmp_path)


def test_source_upload_returns_server_path_and_detected_language(monkeypatch, tmp_path: Path) -> None:
    _use_temp_upload_root(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/uploads",
            params={"filename": "审计 样本.py", "target_type": "source"},
            content=b"print('controlled sample')\n",
            headers={"Content-Type": "application/octet-stream"},
        )

    assert response.status_code == 201
    result = response.json()
    assert result["language"] == "python"
    assert result["stored_path"].startswith("artifacts/uploads/")
    assert result["stored_path"].endswith("/sample.py")
    destination = tmp_path / result["stored_path"]
    assert destination.read_bytes() == b"print('controlled sample')\n"
    assert len(result["sha256"]) == 64


def test_cpp_source_upload_is_supported(monkeypatch, tmp_path: Path) -> None:
    _use_temp_upload_root(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/uploads",
            params={"filename": "service.cpp", "target_type": "source"},
            content=b"int main() { return 0; }\n",
        )

    assert response.status_code == 201
    assert response.json()["language"] == "cpp"


def test_binary_upload_requires_real_elf_or_pe_magic(monkeypatch, tmp_path: Path) -> None:
    _use_temp_upload_root(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        rejected = client.post(
            "/api/uploads",
            params={"filename": "not-really.exe", "target_type": "binary"},
            content=b"plain text",
        )
        accepted = client.post(
            "/api/uploads",
            params={"filename": "teaching.exe", "target_type": "binary"},
            content=b"MZ" + bytes(64),
        )

    assert rejected.status_code == 415
    assert accepted.status_code == 201
    assert accepted.json()["file_format"] == "PE"


def test_upload_rejects_wrong_source_extension_and_oversize_header(monkeypatch, tmp_path: Path) -> None:
    _use_temp_upload_root(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        wrong_type = client.post(
            "/api/uploads",
            params={"filename": "payload.exe", "target_type": "source"},
            content=b"MZ" + bytes(8),
        )
        oversize = client.post(
            "/api/uploads",
            params={"filename": "large.py", "target_type": "source"},
            content=b"x",
            headers={"Content-Length": str(uploads.MAX_UPLOAD_BYTES + 1)},
        )

    assert wrong_type.status_code == 415
    assert oversize.status_code == 413
