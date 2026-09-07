"""FastAPI application factory and default app."""

from fastapi import FastAPI

from vulnagent.api.routes import evidence, findings, health, reports, tasks
from vulnagent.bootstrap import build_mock_services
from vulnagent.settings import get_settings


def create_app() -> FastAPI:
    """Create an isolated application with process-local V0.1 services."""
    settings = get_settings()
    application = FastAPI(title=settings.app_name, version="0.1.0")
    task_manager, evidence_store, orchestrator = build_mock_services()
    application.state.task_manager = task_manager
    application.state.evidence_store = evidence_store
    application.state.orchestrator = orchestrator
    application.include_router(health.router)
    application.include_router(tasks.router)
    application.include_router(findings.router)
    application.include_router(evidence.router)
    application.include_router(reports.router)
    application.include_router(health.router, prefix="/api")
    application.include_router(tasks.router, prefix="/api")
    application.include_router(findings.router, prefix="/api")
    application.include_router(evidence.router, prefix="/api")
    application.include_router(reports.router, prefix="/api")
    return application


app = create_app()
