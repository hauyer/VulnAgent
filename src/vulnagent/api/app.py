"""FastAPI application factory and default app."""

from fastapi import FastAPI

from vulnagent.api.routes import evidence, findings, health, reports, tasks, verifications
from vulnagent.bootstrap import ApplicationServices, build_profile_application
from vulnagent.settings import Settings, get_settings


def create_app(
    *,
    settings: Settings | None = None,
    services: ApplicationServices | None = None,
) -> FastAPI:
    """Create an isolated API backed by one canonical service graph."""
    resolved_settings = settings if settings is not None else get_settings()
    resolved_services = (
        services if services is not None else build_profile_application(resolved_settings)
    )
    application = FastAPI(title=resolved_settings.app_name, version="0.3.0")
    application.state.services = resolved_services
    application.state.task_manager = resolved_services.task_manager
    application.state.evidence_store = resolved_services.evidence_store
    application.state.orchestrator = resolved_services.orchestrator
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
    return application


app = create_app()
