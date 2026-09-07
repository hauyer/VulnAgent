"""FastAPI application factory and default app."""

from fastapi import FastAPI

from vulnagent.api.routes import findings, health, tasks
from vulnagent.core.orchestrator import Orchestrator
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore
from vulnagent.settings import get_settings


def create_app() -> FastAPI:
    """Create an isolated application with process-local V0.1 services."""
    settings = get_settings()
    application = FastAPI(title=settings.app_name, version="0.1.0")
    task_manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    application.state.task_manager = task_manager
    application.state.evidence_store = evidence_store
    application.state.orchestrator = Orchestrator(task_manager, evidence_store)
    application.include_router(health.router)
    application.include_router(tasks.router)
    application.include_router(findings.router)
    return application


app = create_app()

