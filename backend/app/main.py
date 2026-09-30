"""FastAPI application factory.

Run from the backend/ directory:
    python -m uvicorn app.main:app --reload --port 8000
"""

import logging
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.agents.monitor.config import MonitorConfigError, load_monitor_config
from app.agents.compliance.config import ComplianceConfigError, load_compliance_settings
from app.agents.investigator.config import InvestigatorConfigError, load_investigator_config
from app.agents.verification.config import VerificationConfigError, load_verification_rules
from app.agents.remediation.config import RemediationConfigError, load_remediation_settings
from app.agents.triage.config import TriageConfigError, load_triage_config
from app.api.routes import router
from app.config import ConfigurationError, Settings, configure_logging, get_settings
from app.database.connection import Database
from app.llm.base import LLMProvider
from app.llm.factory import LLMConfigurationError, build_provider
from app.services.errors import DatabaseUnavailableError, EventStorageError
from app.simulator.attacks import AttackSimulator, UnknownScenarioError
from app.simulator.cloud import CloudSimulator, ResourceNotFoundError
from app.simulator.events import InvalidEventError
from app.tools.registry import build_default_registry

logger = logging.getLogger(__name__)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message})


_FROM_SETTINGS: Any = object()


def create_app(cloud: CloudSimulator | None = None, database: Database | None = None,
               settings: Settings | None = None,
               llm_provider: LLMProvider | None = _FROM_SETTINGS) -> FastAPI:
    """Build the app. Tests pass their own cloud/database/LLM provider; normally all come
    from .env. The LLM is optional: without it only the Triage run reports a failure."""
    if settings is None:
        try:
            settings = get_settings()
        except ConfigurationError as exc:
            configure_logging()
            logger.error("%s; falling back to defaults", exc)
            settings = Settings()
    configure_logging(settings.log_level)
    if database is None:
        database = Database.from_url(settings.database_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.database.ensure_schema()
        except SQLAlchemyError as exc:
            logger.error("database unavailable at startup (%s); will retry per request",
                         type(exc).__name__)
        yield

    app = FastAPI(title="AgentSOC API", version=__version__,
                  description="Simulated cloud SOC backend. No real AWS. The optional local LLM "
                              "proposes remediation plans and the other reasoning agents, behind strict validation; it never executes anything.",
                  lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
    app.state.settings = settings
    app.state.cloud = cloud or CloudSimulator()
    app.state.attacks = AttackSimulator(app.state.cloud)
    app.state.database = database
    app.state.tools = build_default_registry(agent_actions_enabled=settings.agent_actions_enabled)
    try:
        app.state.monitor_config = load_monitor_config(settings.config_dir)
    except MonitorConfigError as exc:  # the rest of the API still works; the Monitor reports 503
        logger.error("%s", exc)
        app.state.monitor_config = None
    try:
        app.state.triage_config = load_triage_config(settings.config_dir)
    except TriageConfigError as exc:
        logger.error("%s", exc)
        app.state.triage_config = None
    try:
        app.state.investigator_config = load_investigator_config(settings.config_dir)
    except InvestigatorConfigError as exc:
        logger.error("%s", exc)
        app.state.investigator_config = None
    try:
        app.state.compliance_settings = load_compliance_settings(settings.config_dir)
    except ComplianceConfigError as exc:
        logger.error("%s", exc)
        app.state.compliance_settings = None
    try:
        app.state.remediation_settings = load_remediation_settings(settings.config_dir)
    except RemediationConfigError as exc:
        logger.error("%s", exc)
        app.state.remediation_settings = None
    try:
        app.state.verification_rules = load_verification_rules(settings.config_dir)
    except VerificationConfigError as exc:
        logger.error("%s", exc)
        app.state.verification_rules = None
    app.state.llm_error = None
    if llm_provider is _FROM_SETTINGS:
        try:
            llm_provider = build_provider(settings)
        except LLMConfigurationError as exc:  # bad LLM settings must not take the API down
            logger.error("LLM disabled: %s", exc)
            app.state.llm_error = str(exc)
            llm_provider = None
    app.state.llm = llm_provider
    app.state.run_lock = Lock()

    @app.get("/")
    def root() -> dict[str, Any]:
        """Project info."""
        return {"project": "AgentSOC", "version": __version__, "api": "/api", "docs": "/docs"}

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness check (kept from Phase 1; the frontend uses /api/healthz)."""
        return {"status": "healthy"}

    app.include_router(router)

    @app.exception_handler(ResourceNotFoundError)
    async def _not_found(_: Request, exc: ResourceNotFoundError) -> JSONResponse:
        return _error(404, str(exc))

    @app.exception_handler(UnknownScenarioError)
    async def _bad_scenario(_: Request, exc: UnknownScenarioError) -> JSONResponse:
        return _error(400, str(exc))

    @app.exception_handler(InvalidEventError)
    async def _bad_event(_: Request, exc: InvalidEventError) -> JSONResponse:
        return _error(422, str(exc))

    @app.exception_handler(DatabaseUnavailableError)
    async def _db_down(_: Request, exc: DatabaseUnavailableError) -> JSONResponse:
        return _error(503, str(exc))

    @app.exception_handler(EventStorageError)
    async def _storage(_: Request, exc: EventStorageError) -> JSONResponse:
        return _error(500, str(exc))

    return app


app = create_app()
