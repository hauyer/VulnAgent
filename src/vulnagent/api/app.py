"""FastAPI application factory and default app."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from vulnagent.api.routes import (
    acceptance,
    evidence,
    findings,
    health,
    llm_vulnerability,
    poc,
    reports,
    reviews,
    tasks,
    testlab,
    uploads,
    verifications,
)
from vulnagent.bootstrap import ApplicationServices, build_profile_application
from vulnagent.settings import Settings, get_settings
from vulnagent.testlab import TestLabService
from vulnagent.testlab.llm_vuln_scanner import LLMVulnerabilityScanner
from vulnagent.llm.ollama_local import OllamaLocalClient
from vulnagent.review import ReviewAnnotationStore
from vulnagent.acceptance import AcceptanceBatchStore
from vulnagent.poc import ControlledPocService, ControlledPocStore


LOCAL_FRONTEND_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:4173",
    "http://localhost:4173",
]


def _mount_built_frontend(application: FastAPI, repository_root: Path) -> bool:
    """Serve the production UI from FastAPI when ``npm run build`` has run.

    API routes are registered before this catch-all mount, so ``/api`` and the
    legacy unprefixed endpoints keep their existing behavior.  Returning a
    boolean keeps the optional deployment behavior easy to verify in tests.
    """

    frontend_dist = repository_root / "dist"
    if not (frontend_dist / "index.html").is_file():
        return False
    application.mount(
        "/",
        StaticFiles(directory=frontend_dist, html=True),
        name="frontend",
    )
    return True


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
    application = FastAPI(title=resolved_settings.app_name, version="0.4.0")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=LOCAL_FRONTEND_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )
    application.state.services = resolved_services
    application.state.task_manager = resolved_services.task_manager
    application.state.evidence_store = resolved_services.evidence_store
    application.state.orchestrator = resolved_services.orchestrator
    application.state.test_lab = TestLabService(resolved_services)
    ollama_client = OllamaLocalClient(
        base_url=resolved_settings.ollama_base_url,
        timeout_seconds=resolved_settings.ollama_scan_timeout_seconds,
        response_limit=resolved_settings.ollama_scan_response_limit,
        num_gpu=resolved_settings.ollama_scan_num_gpu,
    )
    application.state.llm_vulnerability_scanner = LLMVulnerabilityScanner(
        resolved_services,
        ollama_client,
        configured_models=[
            (
                "DeepSeek R1 1.5B",
                resolved_settings.ollama_deepseek_model,
                "DeepSeek",
            ),
            (
                "Qwen2.5 1.5B",
                resolved_settings.ollama_qwen_model,
                "Qwen",
            ),
        ],
        max_tokens=resolved_settings.ollama_scan_max_tokens,
        log_excerpt=resolved_settings.ollama_scan_log_excerpt,
    )
    application.state.review_annotations = ReviewAnnotationStore(
        Path(__file__).resolve().parents[3] / "artifacts" / "review-annotations.json"
    )
    application.state.acceptance_batches = AcceptanceBatchStore(
        Path(__file__).resolve().parents[3] / "artifacts" / "acceptance-batches.json"
    )
    repository_root = Path(__file__).resolve().parents[3]
    poc_artifacts_root = repository_root / "artifacts" / "controlled-poc"
    application.state.controlled_poc = ControlledPocService(
        repository_root=repository_root,
        task_manager=resolved_services.task_manager,
        orchestrator=resolved_services.orchestrator,
        store=ControlledPocStore(
            repository_root / "artifacts" / "controlled-poc.json",
            poc_artifacts_root,
        ),
    )
    application.include_router(health.router)
    application.include_router(tasks.router)
    application.include_router(testlab.router)
    application.include_router(llm_vulnerability.router)
    application.include_router(poc.router)
    application.include_router(findings.router)
    application.include_router(evidence.router)
    application.include_router(reports.router)
    application.include_router(reviews.router)
    application.include_router(verifications.router)
    application.include_router(uploads.router)
    application.include_router(acceptance.router)
    application.include_router(health.router, prefix="/api")
    application.include_router(tasks.router, prefix="/api")
    application.include_router(testlab.router, prefix="/api")
    application.include_router(llm_vulnerability.router, prefix="/api")
    application.include_router(poc.router, prefix="/api")
    application.include_router(findings.router, prefix="/api")
    application.include_router(evidence.router, prefix="/api")
    application.include_router(reports.router, prefix="/api")
    application.include_router(reviews.router, prefix="/api")
    application.include_router(verifications.router, prefix="/api")
    application.include_router(uploads.router, prefix="/api")
    application.include_router(acceptance.router, prefix="/api")
    application.state.frontend_mounted = _mount_built_frontend(
        application,
        repository_root,
    )
    return application


app = create_app()
