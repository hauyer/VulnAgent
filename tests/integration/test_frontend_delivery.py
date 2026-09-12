from fastapi import FastAPI
from fastapi.testclient import TestClient

from vulnagent.api.app import _mount_built_frontend, create_app


def test_built_frontend_is_served_without_shadowing_api(tmp_path) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text(
        "<!doctype html><title>VulnAgent UI</title>",
        encoding="utf-8",
    )
    application = FastAPI()

    @application.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    assert _mount_built_frontend(application, tmp_path) is True
    with TestClient(application) as client:
        assert client.get("/").status_code == 200
        assert "VulnAgent UI" in client.get("/").text
        assert client.get("/api/health").json() == {"status": "ok"}


def test_frontend_mount_is_optional_when_dist_is_missing(tmp_path) -> None:
    assert _mount_built_frontend(FastAPI(), tmp_path) is False


def test_local_vite_origin_can_fall_back_to_fastapi() -> None:
    with TestClient(create_app()) as client:
        response = client.options(
            "/api/health",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
