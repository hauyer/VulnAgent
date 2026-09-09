"""FastAPI application factory and default app."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from vulnagent.api.routes import evidence, findings, health, reports, tasks, verifications
from vulnagent.bootstrap import build_mock_services
from vulnagent.settings import get_settings


def create_app() -> FastAPI:
    """Create an isolated application with process-local V0.2 services."""
    settings = get_settings()
    application = FastAPI(title=settings.app_name, version="0.2.0")

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    task_manager, evidence_store, orchestrator = build_mock_services()
    application.state.task_manager = task_manager
    application.state.evidence_store = evidence_store
    application.state.orchestrator = orchestrator

    application.include_router(health.router)
    application.include_router(tasks.router)
    application.include_router(findings.router)
    application.include_router(evidence.router)
    application.include_router(reports.router)
    application.include_router(verifications.router)

    application.include_router(health.router, prefix="/api")
    application.include_router(tasks.router, prefix="/api")
    application.include_router(findings.router, prefix="/api")
    application.include_router(evidence.router, prefix="/api")
    application.include_router(reports.router, prefix="/api")
    application.include_router(verifications.router, prefix="/api")

    # Vite build output: frontend/dist/ (with fallback to frontend/)
    # For development, run `npm run dev` in frontend/ (proxies /api to :8000)
    frontend_dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    frontend_dir = Path(__file__).resolve().parents[3] / "frontend"
    if frontend_dist.is_dir():
        application.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
    elif frontend_dir.is_dir():
        application.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return application


app = create_app()

